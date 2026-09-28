"""
risk_rules.py — Deterministic, offline heuristics that flag commonly
risky exposures. These run regardless of whether an LLM is available,
so the tool always produces a meaningful signal, not just a port list.
"""

from dataclasses import dataclass
from .result_parser import HostResult, PortResult

RISKY_SERVICES = {
    21: ("FTP", "Often allows anonymous or cleartext-credential access."),
    23: ("Telnet", "Cleartext protocol; credentials and traffic are unencrypted."),
    25: ("SMTP", "Open relay risk if misconfigured."),
    135: ("MSRPC", "Common lateral-movement target on Windows networks."),
    139: ("NetBIOS", "Legacy SMB transport; often paired with weak auth."),
    445: ("SMB", "Frequent target for worms/ransomware (e.g. EternalBlue-class bugs)."),
    1433: ("MSSQL", "Database exposed directly to network — verify auth and firewalling."),
    3306: ("MySQL", "Database exposed directly to network — verify auth and firewalling."),
    3389: ("RDP", "High-value target for credential stuffing / brute force."),
    5432: ("PostgreSQL", "Database exposed directly to network — verify auth and firewalling."),
    5900: ("VNC", "Remote desktop protocol frequently deployed with weak/no auth."),
    6379: ("Redis", "Historically deployed with no authentication by default."),
    9200: ("Elasticsearch", "Frequently exposed with no auth; a common data-leak source."),
    27017: ("MongoDB", "Historically deployed with no authentication by default."),
}


@dataclass
class RiskFlag:
    host: str
    port: int
    service_label: str
    reason: str
    severity: str  # info | medium | high


def evaluate_host(host: HostResult) -> list[RiskFlag]:
    flags: list[RiskFlag] = []
    for p in host.open_ports():
        if p.port in RISKY_SERVICES:
            label, reason = RISKY_SERVICES[p.port]
            severity = "high" if p.port in (445, 3389, 23, 6379, 9200, 27017) else "medium"
            flags.append(RiskFlag(host=host.address, port=p.port, service_label=label, reason=reason, severity=severity))

    # Unusually large open surface
    if len(host.open_ports()) >= 15:
        flags.append(
            RiskFlag(
                host=host.address,
                port=0,
                service_label="Large attack surface",
                reason=f"{len(host.open_ports())} open ports detected on a single host.",
                severity="medium",
            )
        )
    return flags


def evaluate_report(hosts: list[HostResult]) -> list[RiskFlag]:
    all_flags: list[RiskFlag] = []
    for h in hosts:
        all_flags.extend(evaluate_host(h))
    return all_flags
