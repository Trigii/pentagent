"""LLM-augmented planner.

Wraps a deterministic HeuristicPlanner and asks an LLM to re-rank its
candidates (and optionally propose new ones) using the current graph as
context. The output is validated against a tight schema — if validation
fails we fall back to the heuristic ordering, so a broken prompt or a
hallucinating model can't stall or hijack the run.

**Loop prevention**: the LLM can hallucinate params (e.g. nuclei with
severity='high,middle', 'critical,high,fuzz') and, because each variation
changes the params hash, they all look like new actions. To prevent the
orchestrator from looping on the same tool-vs-target, we dedupe by
`Action.signature()` (tool + canonical target) — not by dedup_key — and
we also reject LLM actions whose signature has already been executed
(from the knowledge store's action_log).
"""
from __future__ import annotations

import json as _json
from dataclasses import dataclass
from typing import Any

from ..llm import LLMClient, LLMMessage
from ..logging_setup import get_logger
from ..memory import KnowledgeStore
from ..prompts.templates import render_planner_prompt, SYSTEM_PROMPT
from .actions import Action, ActionPriority, _canonical_target
from .heuristics import HeuristicPlanner


logger = get_logger(__name__)


def _executed_signatures(store: KnowledgeStore) -> set[str]:
    """Read action_log and return the set of signatures already run, so
    re-proposals can be rejected. Uses canonical target extraction so
    varied param blobs collapse correctly."""
    sigs: set[str] = set()
    try:
        cur = store._conn.execute("SELECT tool, params FROM action_log")
        for row in cur:
            tool = row["tool"]
            try:
                p = _json.loads(row["params"]) if row["params"] else {}
            except Exception:
                p = {}
            sigs.add(f"{tool}::{_canonical_target(p)}")
    except Exception as e:
        logger.debug(f"_executed_signatures failed: {e}")
    return sigs


def _dedupe_by_signature(actions: list[Action], extra_seen: set[str] | None = None) -> list[Action]:
    """Keep the first action per signature. `extra_seen` lets callers pre-
    seed signatures that should be rejected (e.g. already-executed)."""
    seen: set[str] = set(extra_seen or ())
    out: list[Action] = []
    for a in actions:
        sig = a.signature()
        if not sig or sig in seen:
            continue
        seen.add(sig)
        out.append(a)
    return out


@dataclass
class LLMPlanner:
    llm: LLMClient

    def rerank(
        self,
        store: KnowledgeStore,
        candidates: list[Action],
        *,
        budget: dict[str, Any],
    ) -> list[Action]:
        if not candidates:
            return candidates
        graph = store.snapshot()
        prompt = render_planner_prompt(graph=graph, candidates=candidates, budget=budget)
        try:
            resp = self.llm.chat(
                [
                    LLMMessage(role="system", content=SYSTEM_PROMPT),
                    LLMMessage(role="user", content=prompt),
                ],
                expect_json=True,
                temperature=0.1,
            )
            parsed = resp.json()
        except Exception as e:
            logger.warning(f"LLM re-rank failed, using heuristic order: {e}")
            return candidates

        # Expected shape:
        # { "ranking": [{"dedup_key": str, "priority": int}, ...],
        #   "done": bool, "reason": str, "new_actions": [Action-shaped dicts] }
        if not isinstance(parsed, dict):
            return candidates

        by_key = {a.dedup_key(): a for a in candidates}
        ranked: list[Action] = []
        for entry in parsed.get("ranking") or []:
            key = entry.get("dedup_key")
            a = by_key.pop(key, None)
            if a:
                a.priority = int(entry.get("priority", a.priority))
                ranked.append(a)
        # Append any candidates the LLM didn't touch
        ranked.extend(by_key.values())

        # New actions the LLM proposed (must be in the closed tool vocab).
        # Reject any whose signature already ran or duplicates an existing
        # candidate's signature — this is what prevents the nuclei loop.
        executed = _executed_signatures(store)
        existing_sigs = {a.signature() for a in ranked}
        for na in parsed.get("new_actions") or []:
            if not isinstance(na, dict):
                continue
            try:
                a = Action(
                    tool=str(na["tool"]),
                    params=dict(na.get("params") or {}),
                    reason=str(na.get("reason") or "llm-proposed"),
                    expected_signal=str(na.get("expected_signal") or ""),
                    priority=int(na.get("priority") or ActionPriority.normal),
                    parser_context=dict(na.get("parser_context") or {}),
                )
            except Exception:
                continue
            sig = a.signature()
            if not sig:
                logger.debug(f"llm new_action rejected: empty signature tool={a.tool}")
                continue
            if sig in executed:
                logger.info(f"llm new_action rejected: signature already executed ({sig})")
                continue
            if sig in existing_sigs:
                logger.debug(f"llm new_action rejected: duplicates heuristic ({sig})")
                continue
            existing_sigs.add(sig)
            ranked.append(a)

        # Final pass: drop any ranked action whose signature is already in
        # the execution history. This catches the case where heuristics
        # failed to dedupe (e.g. stale state) AND an LLM-promoted ordering
        # brought an already-executed action to the top.
        ranked = [a for a in ranked if a.signature() not in executed]

        # Phase-aware ordering: earlier phase wins, ties by priority.
        ranked.sort(key=lambda a: a.sort_key())
        return ranked

    def is_done(self, store: KnowledgeStore) -> tuple[bool, str]:
        """Ask the LLM whether the session should end."""
        try:
            graph = store.snapshot()
            resp = self.llm.chat(
                [
                    LLMMessage(role="system", content=SYSTEM_PROMPT),
                    LLMMessage(
                        role="user",
                        content=(
                            "Given this knowledge graph, is the pentest complete enough "
                            "to write a useful report? Respond JSON: "
                            "{\"done\": bool, \"reason\": str}\n\n"
                            + _json.dumps(graph, default=str)[:12000]
                        ),
                    ),
                ],
                expect_json=True,
                temperature=0.0,
            )
            out = resp.json()
            return bool(out.get("done", False)), str(out.get("reason", ""))
        except Exception as e:
            logger.debug(f"is_done check failed: {e}")
            return False, "llm_unavailable"


@dataclass
class HybridPlanner:
    """Composition: heuristics produce candidates, LLM re-ranks.

    The LLM is only consulted when it can add value — i.e. when heuristics
    produce *multiple* viable candidates that need ranking. For 0 or 1
    candidates we skip the LLM entirely. This matters on Ollama where a
    single planner call is 30-60s; wasted calls double session wallclock.
    """
    heuristics: HeuristicPlanner
    llm_planner: LLMPlanner | None = None
    # Skip LLM when we have <= this many candidates (nothing to rank).
    llm_min_candidates: int = 2

    def propose(
        self,
        store: KnowledgeStore,
        seed_targets: list[str],
        *,
        budget: dict[str, Any],
    ) -> list[Action]:
        cands = self.heuristics.propose(store, seed_targets)

        # Structural dedupe first — signature-based, stricter than
        # dedup_key. Also filter actions whose signature already ran.
        executed = _executed_signatures(store)
        cands = _dedupe_by_signature(cands, extra_seen=executed)

        if not cands:
            return cands

        # Ask the LLM only when there's a real ranking decision to make.
        if self.llm_planner and len(cands) >= self.llm_min_candidates:
            cands = self.llm_planner.rerank(store, cands, budget=budget)
            # Re-dedupe in case the LLM injected fresh duplicates
            cands = _dedupe_by_signature(cands, extra_seen=executed)
        else:
            logger.debug(
                f"skipping LLM rerank ({len(cands)} candidate(s); "
                f"threshold={self.llm_min_candidates})"
            )

        return cands
