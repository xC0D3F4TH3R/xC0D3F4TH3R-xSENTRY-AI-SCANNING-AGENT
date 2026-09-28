"""
cli.py — SentryScan command-line entrypoint.

Two modes:
    sentryscan scan  "..."   Single nmap pass + report (original behavior)
    sentryscan agent "..."   Autonomous chain: nmap -> decide -> run follow-up
                              tools on whatever ports/services were found ->
                              combined report. This is the default subcommand.

Examples:
    sentryscan agent "recon 192.168.1.10, it's a web server"
    sentryscan agent "check 10.0.0.5 for anything obviously misconfigured" --deep --yes
    sentryscan scan  "quick check if 10.0.0.5 has any open ports" --yes
"""

import argparse
import sys

from .intent_parser import parse_intent, intent_to_nmap_args
from .safety import require_authorization, AuthorizationDenied, UnsafeRequest
from .scanner import run_scan, NmapNotFound, ScanFailed
from .result_parser import parse_nmap_xml
from .summarizer import build_summary
from .agent import run_agent
from .agent_report import render_report


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentryscan",
        description="NLP-driven recon agent: describe a target in plain English; "
                     "it plans and chains scanning tools automatically.",
    )
    sub = p.add_subparsers(dest="mode")

    agent_p = sub.add_parser("agent", help="Autonomous chained recon (nmap + auto-selected follow-up tools).")
    agent_p.add_argument("request", nargs="+", help="Natural-language recon request.")
    agent_p.add_argument("--yes", action="store_true", help="Skip interactive authorization prompt.")
    agent_p.add_argument("--no-llm", action="store_true", help="Disable LLM-assisted intent parsing.")
    agent_p.add_argument("--deep", action="store_true",
                          help="Also allow intrusive follow-up tools (e.g. directory brute-forcing). Opt-in only.")
    agent_p.add_argument("--dry-run", action="store_true", help="Preview the plan without executing anything.")
    agent_p.add_argument("--timeout", type=int, default=60, help="Per-tool timeout in seconds (default 60).")
    agent_p.add_argument("--out", metavar="FILE", help="Write the report to a file as well as stdout.")

    scan_p = sub.add_parser("scan", help="Single nmap pass only (no chained follow-up tools).")
    scan_p.add_argument("request", nargs="+", help="Natural-language scan request.")
    scan_p.add_argument("--yes", action="store_true")
    scan_p.add_argument("--no-llm", action="store_true")
    scan_p.add_argument("--dry-run", action="store_true")
    scan_p.add_argument("--out", metavar="FILE")

    return p


def cmd_scan(args) -> int:
    request_text = " ".join(args.request)
    intent = parse_intent(request_text, use_llm=not args.no_llm)

    if not intent.target:
        print("Could not identify a scan target in your request.", file=sys.stderr)
        return 2

    nmap_args = intent_to_nmap_args(intent)
    print(f"Parsed intent -> nmap {' '.join(nmap_args)} {intent.target}\n")

    if args.dry_run:
        print("[dry-run] Not executing.")
        return 0

    try:
        require_authorization(intent.target, assume_yes=args.yes)
    except (AuthorizationDenied, UnsafeRequest) as e:
        print(f"[blocked] {e}", file=sys.stderr)
        return 1

    try:
        result = run_scan(intent.target, nmap_args)
    except NmapNotFound as e:
        print(f"[error] {e}", file=sys.stderr)
        return 3
    except ScanFailed as e:
        print(f"[error] {e}", file=sys.stderr)
        return 4

    report = parse_nmap_xml(result.xml_output, command=["nmap", *nmap_args, intent.target])
    summary = build_summary(report, intent_reason=intent.reason)
    print(summary)
    if args.out:
        with open(args.out, "w") as f:
            f.write(summary)
        print(f"\n[saved] Report written to {args.out}")
    return 0


def cmd_agent(args) -> int:
    request_text = " ".join(args.request)
    try:
        run = run_agent(
            request_text,
            use_llm=not args.no_llm,
            assume_yes=args.yes,
            deep=args.deep,
            dry_run=args.dry_run,
            per_tool_timeout=args.timeout,
        )
    except ValueError as e:
        print(f"[error] {e}", file=sys.stderr)
        return 2
    except (AuthorizationDenied, UnsafeRequest) as e:
        print(f"[blocked] {e}", file=sys.stderr)
        return 1
    except NmapNotFound as e:
        print(f"[error] {e}", file=sys.stderr)
        return 3
    except ScanFailed as e:
        print(f"[error] {e}", file=sys.stderr)
        return 4

    if run is None:
        return 0  # dry-run already printed its own preview

    report = render_report(run)
    print("\n" + report)
    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"\n[saved] Report written to {args.out}")
    return 0


def main(argv=None) -> int:
    parser = build_argparser()
    args = parser.parse_args(argv)

    if args.mode is None:
        parser.print_help()
        return 2
    if args.mode == "scan":
        return cmd_scan(args)
    return cmd_agent(args)


if __name__ == "__main__":
    sys.exit(main())
