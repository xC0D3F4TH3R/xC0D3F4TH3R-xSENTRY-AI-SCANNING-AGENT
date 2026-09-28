"""
agent_report.py — Renders an AgentRun into a readable report, combining
nmap findings, risk-rule flags, and every chained tool's findings.
"""

from .agent import AgentRun, optional_llm_plan_annotations

SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "info": "🔵"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2}


def render_report(run: AgentRun) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append("SentryScan Agent Report")
    lines.append("=" * 70)
    lines.append(f"Target request: {run.intent.raw_request}")
    lines.append(run.intent.reason)
    lines.append("")

    if not run.nmap_report.hosts:
        lines.append("No hosts responded to the initial port scan. Agent chain not triggered.")
        return "\n".join(lines)

    lines.append("-" * 70)
    lines.append("Stage 1 — Port Discovery (nmap)")
    lines.append("-" * 70)
    for host in run.nmap_report.hosts:
        op = host.open_ports()
        lines.append(f"Host {host.address} ({host.hostname or 'no hostname'}) — {host.state}")
        if host.os_guess:
            lines.append(f"  OS guess: {host.os_guess}")
        if not op:
            lines.append("  No open ports.")
        else:
            for p in sorted(op, key=lambda x: x.port):
                lines.append(f"    - {p.port}/{p.protocol:<3} {p.banner()}")
    lines.append("")

    ran_steps = [s for s in run.steps if s.result.ran]
    skipped_steps = [s for s in run.steps if not s.result.ran]

    lines.append("-" * 70)
    lines.append(f"Stage 2 — Chained Tool Execution ({len(ran_steps)} run, {len(skipped_steps)} skipped)")
    lines.append("-" * 70)
    for step in ran_steps:
        n = len(step.result.findings)
        lines.append(f"  ✔ {step.tool:<16} {step.host}:{step.port}  ({n} finding{'s' if n != 1 else ''})")
    for step in skipped_steps:
        lines.append(f"  ⏭ {step.tool:<16} {step.host}:{step.port}  skipped — {step.result.skipped_reason}")
    lines.append("")

    all_findings = run.all_findings()
    if all_findings:
        lines.append("-" * 70)
        lines.append("Stage 3 — Findings")
        lines.append("-" * 70)
        for f in sorted(all_findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 3)):
            icon = SEVERITY_ICON.get(f.severity, "⚪")
            lines.append(f"  {icon} [{f.severity.upper()}] {f.tool} @ {f.host}:{f.port} ({f.category}) — {f.summary}")
        lines.append("")

    if run.risk_flags:
        lines.append("-" * 70)
        lines.append("Stage 4 — Port-Level Risk Signals")
        lines.append("-" * 70)
        for rf in sorted(run.risk_flags, key=lambda x: SEVERITY_ORDER.get(x.severity, 3)):
            icon = SEVERITY_ICON.get(rf.severity, "⚪")
            where = f"{rf.host}:{rf.port}" if rf.port else rf.host
            lines.append(f"  {icon} [{rf.severity.upper()}] {where} — {rf.service_label}: {rf.reason}")
        lines.append("")

    annotation = optional_llm_plan_annotations(run)
    if annotation:
        lines.append("-" * 70)
        lines.append("AI Triage Notes (what to look at first)")
        lines.append("-" * 70)
        lines.append(annotation)

    return "\n".join(lines)
