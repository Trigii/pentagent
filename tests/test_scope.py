"""Scope is the single most safety-critical component; test it hard."""
from __future__ import annotations

import pytest

from pentagent.safety import Scope, ScopeGuard, ScopeViolation


def _scope(**overrides):
    base = dict(
        program_name="test",
        authorized_by="me",
        authorized_on="2026-01-01",
        authorization_source="tests",
        operator="tester@example.com",
        include=["*.example.com", "example.com"],
        exclude=["admin.example.com"],
        aggressive_opt_in=["api.example.com"],
    )
    base.update(overrides)
    return Scope(**base)


def test_allows_exact_match():
    g = ScopeGuard(_scope())
    g.check("example.com")
    g.check("https://example.com/path")


def test_allows_subdomain_via_wildcard():
    g = ScopeGuard(_scope())
    g.check("api.example.com")
    g.check("https://www.example.com/")


def test_denies_unrelated_host():
    g = ScopeGuard(_scope())
    with pytest.raises(ScopeViolation):
        g.check("evil.com")


def test_exclude_overrides_include():
    g = ScopeGuard(_scope())
    with pytest.raises(ScopeViolation) as ei:
        g.check("https://admin.example.com/login")
    assert "exclude" in str(ei.value).lower()


def test_aggressive_requires_opt_in():
    g = ScopeGuard(_scope())
    # In-scope for passive, but not in aggressive_opt_in
    with pytest.raises(ScopeViolation):
        g.check("https://www.example.com", aggressive=True)
    # This one is
    g.check("https://api.example.com", aggressive=True)


def test_private_ip_requires_explicit_listing():
    # Wildcard or public include should NOT authorize private IPs
    g = ScopeGuard(_scope(include=["*.example.com"]))
    with pytest.raises(ScopeViolation):
        g.check("10.0.0.1")
    # Explicit CIDR is OK
    g2 = ScopeGuard(_scope(include=["*.example.com", "10.0.0.0/24"]))
    g2.check("10.0.0.5")


def test_filter_drops_oos():
    g = ScopeGuard(_scope())
    targets = ["example.com", "evil.com", "https://admin.example.com", "https://www.example.com"]
    out = g.filter(targets)
    assert set(out) == {"example.com", "https://www.example.com"}


def test_scope_load_requires_authorization_fields(tmp_path):
    import yaml
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump({"include": ["*.example.com"]}))
    with pytest.raises(ValueError):
        Scope.load(p)
