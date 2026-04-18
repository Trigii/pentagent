"""Knowledge store invariants — dedup, placeholder remap, snapshot."""
from __future__ import annotations

from pentagent.memory import (
    Endpoint,
    Evidence,
    Finding,
    Host,
    KnowledgeStore,
    Observation,
    Service,
    Severity,
    WebApp,
)


def _store(tmp_path):
    return KnowledgeStore(tmp_path / "k.db")


def test_host_dedup(tmp_path):
    s = _store(tmp_path)
    obs1 = Observation(hosts=[Host(ip="1.2.3.4", hostname="x.example.com")])
    s.commit(obs1)
    obs2 = Observation(hosts=[Host(ip="1.2.3.4", hostname="x.example.com")])
    s.commit(obs2)
    assert len(s.hosts()) == 1


def test_placeholder_remap(tmp_path):
    s = _store(tmp_path)
    obs = Observation(
        hosts=[Host(hostname="www.example.com")],
        services=[Service(host_id=-1, port=443, proto="tcp", product="nginx")],
        webapps=[WebApp(host_id=-1, scheme="https", base_url="https://www.example.com")],
    )
    counts = s.commit(obs)
    assert counts["hosts"] == 1
    assert counts["services"] == 1
    assert counts["webapps"] == 1

    apps = s.webapps()
    assert apps and apps[0].host_id == s.hosts()[0].id


def test_finding_dedup_respects_template(tmp_path):
    s = _store(tmp_path)
    s.commit(Observation(hosts=[Host(hostname="x")]))
    host_id = s.hosts()[0].id
    f1 = Finding(kind="tech-detect", severity=Severity.info, entity_type="Host",
                 entity_id=host_id, title="T", template_id="t1")
    f2 = Finding(kind="tech-detect", severity=Severity.info, entity_type="Host",
                 entity_id=host_id, title="T", template_id="t1")
    s.commit(Observation(findings=[f1]))
    s.commit(Observation(findings=[f2]))
    assert len(s.findings()) == 1


def test_severity_filter(tmp_path):
    s = _store(tmp_path)
    s.commit(Observation(hosts=[Host(hostname="x")]))
    hid = s.hosts()[0].id
    s.commit(Observation(findings=[
        Finding(kind="a", severity=Severity.info, entity_type="Host", entity_id=hid, title="a", template_id="a"),
        Finding(kind="b", severity=Severity.high, entity_type="Host", entity_id=hid, title="b", template_id="b"),
    ]))
    hi = s.findings(severity_gte=Severity.medium)
    assert {f.kind for f in hi} == {"b"}


def test_action_cache(tmp_path):
    s = _store(tmp_path)
    assert not s.action_cached("abc")
    s.record_action(tool="nmap", params_json="{}", started_at=0, finished_at=0,
                    exit_code=0, cache_key="abc")
    assert s.action_cached("abc")
