"""nmap XML parser → Host + Service observations.

Uses the store's placeholder-id convention: a newly-parsed host's position
in `obs.hosts` is i; any Service referencing it sets `host_id = -(i+1)` and
the store remaps it to the real row id during commit.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from ..memory import Host, Observation, Service
from ..tools.base import ToolResult


def parse(result: ToolResult, context: dict) -> Observation:
    obs = Observation(source_tool="nmap", raw_excerpt=result.stdout[:2000])
    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError:
        return obs

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']") or host_el.find(
            "address[@addrtype='ipv6']"
        )
        ip = addr_el.get("addr") if addr_el is not None else None
        hostname = None
        names = host_el.find("hostnames")
        if names is not None:
            hn = names.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        os_guess = None
        os_el = host_el.find("os/osmatch")
        if os_el is not None:
            os_guess = os_el.get("name")

        host = Host(ip=ip, hostname=hostname, os_guess=os_guess)
        obs.hosts.append(host)
        host_idx = len(obs.hosts) - 1
        placeholder = -(host_idx + 1)

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            proto = port_el.get("protocol") or "tcp"
            port_num = int(port_el.get("portid") or 0)
            svc_el = port_el.find("service")
            product = version = banner = None
            if svc_el is not None:
                product = svc_el.get("product") or svc_el.get("name")
                version = svc_el.get("version")
                banner_parts = [
                    svc_el.get("name"),
                    product,
                    version,
                    svc_el.get("extrainfo"),
                ]
                banner = " ".join(p for p in banner_parts if p) or None
            obs.services.append(
                Service(
                    host_id=placeholder,
                    port=port_num,
                    proto=proto,
                    product=product,
                    version=version,
                    banner=banner,
                )
            )

    return obs
