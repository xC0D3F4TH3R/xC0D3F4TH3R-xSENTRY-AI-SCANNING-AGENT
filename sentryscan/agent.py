"""
agent.py — The autonomous recon agent.

Pipeline:
  1. Nmap port discovery (via existing scanner/intent modules) — this is
     ALWAYS the first step; nothing else runs before we know what's open.
  2. Decision engine: for every open port, pick which adapters apply.
  3. Execute each applicable adapter, collecting Finding objects.
  4. Hand everything to the summarizer/risk-rules layer for the report.

Design boundary: the agent decides WHICH of a fixed, pre-approved set of
adapters to run and WHERE (host:port) — it does not construct new shell
commands, does not invent new tools, and does not chain into anything
exploitation-oriented. "Deep" (more intrusive) adapters are opt-in only.
An optional LLM can be asked to prioritize/annotate the plan, but the
plan's action space is still limited to the adapters registered below —
the model can reorder or skip, it cannot add a new command.
"""

import os
import json
from dataclasses import dataclass, field

from .intent_parser import parse_intent, intent_to_nmap_args, ScanIntent
from .safety import require_authorization, AuthorizationDenied, UnsafeRequest
from .scanner import run_scan, NmapNotFound, ScanFailed
from .result_parser import parse_nmap_xml, ScanReport, HostResult
from .risk_rules import evaluate_report, RiskFlag
from .tools.base import Finding, ToolRunResult
from .tools.native_probes import NATIVE_ADAPTERS
from .tools.external_tools import STANDARD_EXTERNAL_ADAPTERS, DEEP_EXTERNAL_ADAPTERS


@dataclass
class AgentStep:
    tool: str
    host: str
    port: int
    result: ToolRunResult


@dataclass
class AgentRun:
    intent: ScanIntent
    nmap_report: ScanReport
    steps: list[AgentStep] = field(default_factory=list)
    risk_flags: list[RiskFlag] = field(default_factory=list)

    def all_findings(self) -> list[Finding]:
        out = []
        for s in self.steps:
            out.extend(s.result.findings)
        return out


def _build_adapter_registry(deep: bool):
    registry = list(NATIVE_ADAPTERS) + list(STANDARD_EXTERNAL_ADAPTERS)
    if deep:
        registry += list(DEEP_EXTERNAL_ADAPTERS)
    return registry


def plan_chain(nmap_report: ScanReport, deep: bool = False) -> list[tuple[str, str, int, object]]:
    """
    The decision engine: given discovered open ports, returns a list of
    (host, service, port, adapter) tuples describing what will run next.
    Pure function, no side effects — used for both --dry-run previews
    and actual execution, so what you preview is exactly what runs.
    """
    registry = _build_adapter_registry(deep)
    plan = []
    for host in nmap_report.hosts:
        for p in host.open_ports():
            for adapter in registry:
                if adapter.applies_to(p.port, p.service):
                    plan.append((host.address, p.service, p.port, adapter))
    return plan


def describe_plan(plan) -> str:
    if not plan:
        return "No follow-up tools apply to the discovered open ports."
    lines = ["Planned follow-up actions:"]
    for host, service, port, adapter in plan:
        avail = "" if adapter.is_available() else "  [SKIP: binary not installed]"
        lines.append(f"  - {adapter.name:<16} -> {host}:{port} ({service or 'unknown'}){avail}")
    return "\n".join(lines)


def run_agent(
    request_text: str,
    use_llm: bool = True,
    assume_yes: bool = False,
    deep: bool = False,
    dry_run: bool = False,
    per_tool_timeout: int = 60,
) -> AgentRun | None:
    """
    Full pipeline entrypoint. Returns None on dry-run or abort.
    """
    intent = parse_intent(request_text, use_llm=use_llm)
    if not intent.target:
        raise ValueError("Could not identify a scan target in the request.")

    nmap_args = intent_to_nmap_args(intent)

    if dry_run:
        print("[dry-run] Parsed intent -> nmap:")
        print(f"  nmap {' '.join(nmap_args)} {intent.target}")
        print("[dry-run] Follow-up chain cannot be previewed fully until ports are known,")
        print("          but here is the adapter registry that WOULD be considered:")
        registry = _build_adapter_registry(deep)
        for a in registry:
            print(f"  - {a.name} (available={a.is_available()})")
        return None

    require_authorization(intent.target, assume_yes=assume_yes)

    # Step 1: port discovery (always first)
    scan_result = run_scan(intent.target, nmap_args)
    nmap_report = parse_nmap_xml(scan_result.xml_output, command=["nmap", *nmap_args, intent.target])

    run = AgentRun(intent=intent, nmap_report=nmap_report)
    run.risk_flags = evaluate_report(nmap_report.hosts)

    # Step 2 + 3: decision engine + chained execution
    plan = plan_chain(nmap_report, deep=deep)
    print(describe_plan(plan))
    print()

    for host, service, port, adapter in plan:
        if not adapter.is_available():
            run.steps.append(AgentStep(
                tool=adapter.name, host=host, port=port,
                result=ToolRunResult(tool_name=adapter.name, ran=False,
                                      skipped_reason=f"'{adapter.requires_binary}' not installed"),
            ))
            continue
        print(f"[agent] Running {adapter.name} against {host}:{port} ...")
        try:
            result = adapter.run(host, port, service, timeout=per_tool_timeout)
        except Exception as e:
            result = ToolRunResult(tool_name=adapter.name, ran=False, skipped_reason=f"error: {e}")
        run.steps.append(AgentStep(tool=adapter.name, host=host, port=port, result=result))

    return run


def optional_llm_plan_annotations(run: AgentRun) -> str | None:
    """
    Optional: ask Claude to prioritize/annotate the *already-collected*
    findings (what to look at first, why it matters). Read-only — cannot
    trigger further tool execution. Requires ANTHROPIC_API_KEY.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        return None

    findings = run.all_findings()
    findings_text = "\n".join(f"- [{f.severity}] {f.tool} {f.host}:{f.port} {f.category}: {f.summary}" for f in findings)
    if not findings_text:
        return None

    prompt = (
        "These are findings from an ALREADY-COMPLETED authorized recon scan "
        "(you are not scanning anything, only analyzing results). Rank the top "
        "3 most important findings an operator should investigate first, and "
        "say why, in under 150 words total.\n\n" + findings_text
    )
    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(model="claude-sonnet-4-5", max_tokens=350,
                                       messages=[{"role": "user", "content": prompt}])
        return "".join(b.text for b in resp.content if hasattr(b, "text")).strip()
    except Exception:
        return None
