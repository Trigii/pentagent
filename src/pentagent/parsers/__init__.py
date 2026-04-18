"""Parsers dispatch table.

Each parser consumes a `ToolResult` and produces an `Observation`. Parsers
are pure — no I/O, no DB writes. The orchestrator commits the observation.
"""
from __future__ import annotations

from typing import Callable

from ..memory import Observation
from ..tools.base import ToolResult
from . import nmap as nmap_parser
from . import httpx as httpx_parser
from . import ffuf as ffuf_parser
from . import nuclei as nuclei_parser
from . import generic as generic_parser


ParserFn = Callable[[ToolResult, dict], Observation]


_PARSERS: dict[str, ParserFn] = {
    "nmap": nmap_parser.parse,
    "httpx": httpx_parser.parse,
    "ffuf": ffuf_parser.parse,
    "nuclei": nuclei_parser.parse,
    "subfinder": generic_parser.parse_subdomain_list,
    "amass": generic_parser.parse_subdomain_list,
    "gobuster": generic_parser.parse_gobuster,
    "katana": generic_parser.parse_katana,
    "nikto": generic_parser.parse_nikto,
    "sqlmap": generic_parser.parse_sqlmap,
}


def parse_for(tool: str, result: ToolResult, context: dict | None = None) -> Observation:
    context = context or {}
    fn = _PARSERS.get(tool)
    if not fn:
        obs = Observation(source_tool=tool, raw_excerpt=result.stdout[:1000])
        return obs
    obs = fn(result, context)
    obs.source_tool = tool
    return obs
