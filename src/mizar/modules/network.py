"""Listening sockets (ss) and, when enabled, an external nmap scan."""

from __future__ import annotations

from typing import Dict, List, Set, Tuple

from mizar.base import Module
from mizar.context import Context
from mizar.models import Finding, SkipReason, Status

RISKY_PORTS = {
    21: "ftp",
    23: "telnet",
    2375: "docker api (unencrypted)",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}
EXPECTED_PUBLIC = {("tcp", 22), ("tcp", 80), ("tcp", 443), ("udp", 68), ("udp", 123)}
PUBLIC_ADDRESSES = {"0.0.0.0", "*", "[::]", "::"}
NMAP_TIMEOUT = 300

Listener = Tuple[str, int]


def parse_public_listeners(output: str) -> Set[Listener]:
    listeners: Set[Listener] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5 or fields[0] not in ("tcp", "udp"):
            continue
        address, _, port = fields[4].rpartition(":")
        if address in PUBLIC_ADDRESSES and port.isdigit():
            listeners.add((fields[0], int(port)))
    return listeners


def _describe(listeners: Set[Listener]) -> str:
    return ", ".join(f"{proto}/{port}" for proto, port in sorted(listeners))


class NetworkModule(Module):
    name = "network"
    profile = "standard"
    tools = ("ss",)
    description = "services listening on public interfaces"

    def run(self, ctx: Context) -> List[Finding]:
        result = ctx.run(["ss", "-tulpn"])
        if result.not_found:
            return [
                self.skip(
                    "network.listeners",
                    "Listening sockets",
                    SkipReason.TOOL_MISSING,
                    "ss not found",
                )
            ]
        public = parse_public_listeners(result.stdout)
        risky = {item for item in public if item[1] in RISKY_PORTS}
        unexpected = {item for item in public - risky if item not in EXPECTED_PUBLIC}
        return [
            self._verdict(
                "network.risky_listeners",
                "Databases and legacy services exposed publicly",
                risky,
                Status.CRIT,
                "Bind these services to 127.0.0.1 or block them in the firewall.",
            ),
            self._verdict(
                "network.public_listeners",
                "Unexpected public listeners",
                unexpected,
                Status.WARN,
                "Confirm each service must be reachable from outside.",
            ),
        ]

    def _verdict(
        self,
        id: str,
        title: str,
        found: Set[Listener],
        bad: Status,
        advice: str,
    ) -> Finding:
        if not found:
            return self.finding(id, Status.OK, title)
        return self.finding(id, bad, title, _describe(found), advice)


def parse_nmap_open_ports(output: str) -> Dict[int, str]:
    ports: Dict[int, str] = {}
    for line in output.splitlines():
        _, sep, rest = line.partition("Ports: ")
        if not sep:
            continue
        for entry in rest.split("\t")[0].split(", "):
            parts = entry.strip().split("/")
            if len(parts) >= 5 and parts[1] == "open" and parts[0].isdigit():
                ports[int(parts[0])] = parts[4]
    return ports


class NmapModule(Module):
    name = "nmap"
    profile = "standard"
    active = True
    tools = ("nmap",)
    description = "external port and service scan of --target"

    def run(self, ctx: Context) -> List[Finding]:
        if not ctx.has("nmap"):
            return [
                self.skip(
                    "nmap.open_ports",
                    "Open ports (nmap)",
                    SkipReason.TOOL_MISSING,
                    "nmap not found",
                )
            ]
        result = ctx.run(
            ["nmap", "-Pn", "-sV", "-oG", "-", ctx.target], timeout=NMAP_TIMEOUT
        )
        if result.timed_out:
            return [
                self.skip(
                    "nmap.open_ports",
                    "Open ports (nmap)",
                    SkipReason.TIMEOUT,
                    f"scan exceeded {NMAP_TIMEOUT}s",
                )
            ]
        open_ports = parse_nmap_open_ports(result.stdout)
        risky = {p: s for p, s in open_ports.items() if p in RISKY_PORTS}
        rest = {p: s for p, s in open_ports.items() if p not in risky}
        listing = ", ".join(f"{p}/{s}" for p, s in sorted(rest.items()))
        findings = [
            self.finding(
                "nmap.open_ports",
                Status.OK,
                f"Open ports on {ctx.target}",
                listing or "none",
            )
        ]
        if risky:
            evidence = ", ".join(f"{p}/{s}" for p, s in sorted(risky.items()))
            findings.append(
                self.finding(
                    "nmap.risky_ports",
                    Status.CRIT,
                    "Risky services reachable",
                    evidence,
                    "Close these ports or restrict them to trusted addresses.",
                )
            )
        else:
            findings.append(
                self.finding("nmap.risky_ports", Status.OK, "Risky services reachable")
            )
        return findings
