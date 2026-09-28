"""
summarizer.py — Turns a ScanReport into a human-readable summary.

Works fully offline via a template summary. If ANTHROPIC_API_KEY is set,
also asks Claude to write a short narrative summary — but the LLM is
only ever given the already-structured, already-parsed findings (ports,
services, risk flags) as text context. It cannot influence the scan
itself and has no tool access, so this step is read-only and safe by
construction.
"""

import os
from .result_parser import ScanReport
from .risk_rules import evaluate_report, RiskFlag


def _severity_icon(sev: str) -> str:
    return {"high": "🔴", "medium": "🟠", "info": "🔵"}.get(sev, "⚪")


def template_summary(report: ScanReport, intent_reason: str = "") -> str:
    lines = []
    lines.append("=" * 64)
    lines.append("SentryScan Report")
    lines.append("=" * 64)
    if intent_reason:
        lines.append(intent_reason)
    lines.append(f"Command: {' '.join(report.raw_command)}")
    lines.append("")

    if not report.hosts:
        lines.append("No hosts responded. Target may be down, filtered, or blocking probes.")
        return "\n".join(lines)

    for host in report.hosts:
        lines.append(f"Host: {host.address} ({host.hostname or 'no hostname'}) — {host.state}")
        if host.os_guess:
            lines.append(f"  OS guess: {host.os_guess}")
        open_ports = host.open_ports()
        if not open_ports:
            lines.append("  No open ports found.")
        else:
            lines.append(f"  {len(open_ports)} open port(s):")
            for p in sorted(open_ports, key=lambda x: x.port):
                lines.append(f"    - {p.port}/{p.protocol:<3} {p.state:<6} {p.banner()}")
        lines.append("")

    flags = evaluate_report(report.hosts)
    if flags:
        lines.append("-" * 64)
        lines.append("Risk Signals")
        lines.append("-" * 64)
        for f in sorted(flags, key=lambda x: {"high": 0, "medium": 1, "info": 2}[x.severity]):
            where = f"{f.host}:{f.port}" if f.port else f.host
            lines.append(f"  {_severity_icon(f.severity)} [{f.severity.upper()}] {where} — {f.service_label}: {f.reason}")
    else:
        lines.append("No high-signal risk patterns matched by local heuristics.")

    return "\n".join(lines)


def llm_narrative_summary(report: ScanReport, flags: list[RiskFlag]) -> str | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    findings_text = []
    for host in report.hosts:
        op = [f"{p.port}/{p.protocol} {p.banner()}" for p in host.open_ports()]
        findings_text.append(f"Host {host.address} ({host.os_guess or 'OS unknown'}): open ports = {op}")
    flag_text = [f"{f.severity}: {f.host}:{f.port} {f.service_label} - {f.reason}" for f in flags]

    prompt = (
        "You are a security analyst. Given these ALREADY-COMPLETED scan findings "
        "(you are not performing any scan yourself, only summarizing), write a "
        "concise 4-6 sentence executive summary for a report. Be factual, avoid "
        "speculation beyond the data given, and end with the single most important "
        "next action.\n\n"
        f"Findings:\n{chr(10).join(findings_text)}\n\n"
        f"Risk flags:\n{chr(10).join(flag_text) if flag_text else 'None'}"
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if hasattr(b, "text")).strip()
    except Exception:
        return None


def build_summary(report: ScanReport, intent_reason: str = "") -> str:
    base = template_summary(report, intent_reason)
    flags = evaluate_report(report.hosts)
    narrative = llm_narrative_summary(report, flags)
    if narrative:
        base += "\n\n" + "-" * 64 + "\nExecutive Summary (AI-generated)\n" + "-" * 64 + "\n" + narrative
    return base
