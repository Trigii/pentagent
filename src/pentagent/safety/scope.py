"""Scope enforcement.

Every tool invocation runs through `ScopeGuard.check(target)` before the
executor is called. If the target is not explicitly in the allowlist, the
invocation is rejected, logged, and the iteration continues. This is the
primary structural defense against misuse.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import yaml


class ScopeViolation(Exception):
    """Raised when a target is outside the authorized scope."""


@dataclass
class Scope:
    program_name: str
    authorized_by: str
    authorized_on: str
    authorization_source: str
    operator: str
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    aggressive_opt_in: list[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        raw = yaml.safe_load(Path(path).read_text())
        required = ("program_name", "authorized_by", "authorized_on", "authorization_source", "operator")
        missing = [k for k in required if not raw.get(k)]
        if missing:
            raise ValueError(
                f"scope file {path!r} is missing required authorization fields: {missing}. "
                "pentagent requires explicit written authorization metadata before it will run."
            )
        return cls(
            program_name=raw["program_name"],
            authorized_by=raw["authorized_by"],
            authorized_on=str(raw["authorized_on"]),
            authorization_source=raw["authorization_source"],
            operator=raw["operator"],
            include=list(raw.get("include", [])),
            exclude=list(raw.get("exclude", [])),
            aggressive_opt_in=list(raw.get("aggressive_opt_in", [])),
            notes=str(raw.get("notes", "")),
        )


class ScopeGuard:
    """Decides whether a target (URL, host, IP) is authorized."""

    def __init__(self, scope: Scope, *, deny_private_unless_explicit: bool = True):
        self.scope = scope
        self.deny_private_unless_explicit = deny_private_unless_explicit
        self._ip_nets: list[ipaddress._BaseNetwork] = []
        self._host_patterns: list[str] = []
        self._exclude_ip_nets: list[ipaddress._BaseNetwork] = []
        self._exclude_host_patterns: list[str] = []
        self._agg_ip_nets: list[ipaddress._BaseNetwork] = []
        self._agg_host_patterns: list[str] = []
        self._split(scope.include, self._ip_nets, self._host_patterns)
        self._split(scope.exclude, self._exclude_ip_nets, self._exclude_host_patterns)
        self._split(scope.aggressive_opt_in, self._agg_ip_nets, self._agg_host_patterns)

    @staticmethod
    def _split(entries: Iterable[str], ip_out: list, host_out: list) -> None:
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            try:
                ip_out.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                host_out.append(entry.lower())

    @staticmethod
    def _extract_host(target: str) -> str:
        """Accept URLs or bare hosts/IPs and return the lowercase hostname/ip."""
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or ""
        else:
            host = target.split("/", 1)[0].split(":", 1)[0]
        return host.lower()

    def _host_matches(self, host: str, patterns: list[str]) -> bool:
        for pat in patterns:
            if fnmatch.fnmatch(host, pat):
                return True
        return False

    def _ip_matches(self, host: str, nets: list) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(ip in net for net in nets)

    def is_private(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip.is_private or ip.is_loopback or ip.is_link_local

    def check(self, target: str, *, aggressive: bool = False) -> None:
        """Raise ScopeViolation if target is not in scope.

        Rules, in order:
          1. If host matches exclude → violation.
          2. If host is a private/loopback IP and we require explicit
             authorization, it must appear verbatim (or by CIDR) in include.
          3. If host matches include (hostname pattern or IP/CIDR) → allowed.
          4. If aggressive=True, host must also match aggressive_opt_in.
        """
        host = self._extract_host(target)
        if not host:
            raise ScopeViolation(f"could not extract host from target {target!r}")

        if self._host_matches(host, self._exclude_host_patterns) or self._ip_matches(host, self._exclude_ip_nets):
            raise ScopeViolation(f"{host} is in the scope EXCLUDE list")

        in_include = (
            self._host_matches(host, self._host_patterns)
            or self._ip_matches(host, self._ip_nets)
        )
        if not in_include:
            raise ScopeViolation(
                f"{host} is not in the scope INCLUDE list (program={self.scope.program_name!r})"
            )

        if self.deny_private_unless_explicit and self.is_private(host):
            # Must be explicitly listed (not just matched by a wildcard)
            if host not in {e.lower() for e in self.scope.include} and not self._ip_matches(host, self._ip_nets):
                raise ScopeViolation(
                    f"{host} is a private/internal address; must be explicitly listed in include"
                )

        if aggressive:
            in_agg = (
                self._host_matches(host, self._agg_host_patterns)
                or self._ip_matches(host, self._agg_ip_nets)
            )
            if not in_agg:
                raise ScopeViolation(
                    f"{host} is not in aggressive_opt_in; destructive checks refused"
                )

    def filter(self, targets: Iterable[str], *, aggressive: bool = False) -> list[str]:
        """Return only the targets that pass scope."""
        out: list[str] = []
        for t in targets:
            try:
                self.check(t, aggressive=aggressive)
                out.append(t)
            except ScopeViolation:
                continue
        return out
