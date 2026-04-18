"""LLM-augmented planner.

Wraps a deterministic HeuristicPlanner and asks an LLM to re-rank its
candidates (and optionally propose new ones) using the current graph as
context. The output is validated against a tight schema — if validation
fails we fall back to the heuristic ordering, so a broken prompt or a
hallucinating model can't stall or hijack the run.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..llm import LLMClient, LLMMessage
from ..logging_setup import get_logger
from ..memory import KnowledgeStore
from ..prompts.templates import render_planner_prompt, SYSTEM_PROMPT
from .actions import Action, ActionPriority
from .heuristics import HeuristicPlanner


logger = get_logger(__name__)


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

        # New actions the LLM proposed (must be in the closed tool vocab)
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
            # de-dupe against existing
            if all(a.dedup_key() != r.dedup_key() for r in ranked):
                ranked.append(a)

        ranked.sort(key=lambda a: -a.priority)
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
                            + json.dumps(graph, default=str)[:12000]
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
    """Composition: heuristics produce candidates, LLM re-ranks."""
    heuristics: HeuristicPlanner
    llm_planner: LLMPlanner | None = None

    def propose(
        self,
        store: KnowledgeStore,
        seed_targets: list[str],
        *,
        budget: dict[str, Any],
    ) -> list[Action]:
        cands = self.heuristics.propose(store, seed_targets)
        if self.llm_planner and cands:
            cands = self.llm_planner.rerank(store, cands, budget=budget)
        return cands
