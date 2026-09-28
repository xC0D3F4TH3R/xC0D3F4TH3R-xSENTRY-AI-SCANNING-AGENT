"""
result_parser.py — Parses Nmap's XML output into clean, typed Python
objects so downstream summarization never touches raw XML/regex soup.
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    reason: str = ""

    def banner(self) -> str:
        bits = [self.service]
        if self.product:
            bits.append(self.product)
        if self.version:
            bits.append(self.version)
        return " ".join(b for b in bits if b).strip() or "unknown"


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    state: str = "unknown"
    os_guess: str = ""
    ports: list[PortResult] = field(default_factory=list)

    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]


@dataclass
class ScanReport:
    raw_command: list[str]
    hosts: list[HostResult] = field(default_factory=list)


def parse_nmap_xml(xml_text: str, command: list[str]) -> ScanReport:
    if not xml_text.strip():
        return ScanReport(raw_command=command, hosts=[])

    root = ET.fromstring(xml_text)
    report = ScanReport(raw_command=command)

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"

        addr_el = host_el.find("address")
        address = addr_el.get("addr") if addr_el is not None else "unknown"

        hostname = ""
        hn_el = host_el.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name", "")

        os_guess = ""
        os_match = host_el.find("os/osmatch")
        if os_match is not None:
            os_guess = os_match.get("name", "")

        host = HostResult(address=address, hostname=hostname, state=state, os_guess=os_guess)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_num = int(port_el.get("portid"))
                proto = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                p_state = state_el.get("state") if state_el is not None else "unknown"
                reason = state_el.get("reason", "") if state_el is not None else ""

                service = product = version = ""
                svc_el = port_el.find("service")
                if svc_el is not None:
                    service = svc_el.get("name", "")
                    product = svc_el.get("product", "")
                    version = svc_el.get("version", "")

                host.ports.append(
                    PortResult(
                        port=port_num,
                        protocol=proto,
                        state=p_state,
                        service=service,
                        product=product,
                        version=version,
                        reason=reason,
                    )
                )

        report.hosts.append(host)

    return report
