"""Tool registry + argv builders."""
from __future__ import annotations

import pytest

from pentagent.tools import default_registry


def test_all_tools_register():
    names = set(default_registry.names())
    expected = {"nmap", "httpx", "subfinder", "amass", "ffuf", "gobuster",
                "nuclei", "sqlmap", "nikto", "katana"}
    assert expected <= names


def test_nmap_builds_argv():
    t = default_registry.get("nmap")
    argv = t.build_argv({"target": "example.com", "ports": "80,443"})
    assert argv[-1] == "example.com"
    assert "-p" in argv


def test_httpx_targets_extraction():
    t = default_registry.get("httpx")
    assert t.targets({"targets": ["a", "b"]}) == ["a", "b"]
    assert t.targets({"target": "x"}) == ["x"]


def test_ffuf_requires_FUZZ_placeholder():
    t = default_registry.get("ffuf")
    with pytest.raises(ValueError):
        t.build_argv({"url": "https://x/", "wordlist": "w.txt"})
    t.build_argv({"url": "https://x/FUZZ", "wordlist": "w.txt"})


def test_sqlmap_is_aggressive_only():
    t = default_registry.get("sqlmap")
    assert t.spec.supports_modes == ("aggressive",)
    assert t.mode_required({"url": "https://x/?id=1"}) == "aggressive"
