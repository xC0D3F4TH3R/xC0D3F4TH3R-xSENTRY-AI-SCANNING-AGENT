"""
safety.py — Authorization gate and blast-radius controls.

SentryScan refuses to run any scan until the operator explicitly confirms
authorization for the exact target(s). This module also blocks a small
set of always-dangerous option combinations regardless of confirmation.
"""

import ipaddress
import re
import sys
from dataclasses import dataclass


class AuthorizationDenied(Exception):
    pass


class UnsafeRequest(Exception):
    pass


AUTH_BANNER = """
================================================================
 SentryScan — Authorized Security Testing Tool
================================================================
 Scanning networks or hosts you do not own or lack explicit
 written permission to test may be illegal in your jurisdiction
 (e.g. Computer Fraud and Abuse Act, Computer Misuse Act, etc).

 By continuing you confirm that:
   1. You own the target(s), OR
   2. You hold documented authorization to test them.
================================================================
"""

# Never allow scanning these regardless of confirmation — reduces
# accidental scans of infrastructure the user almost certainly does
# not own even if they typed "yes".
HARD_BLOCKLIST_PATTERNS = [
    r"^0\.0\.0\.0/0$",
    r"^::/0$",
]


def _is_private_or_loopback(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False  # hostname / CIDR handled elsewhere


@dataclass
class AuthDecision:
    confirmed: bool
    target: str
    note: str = ""


def check_hard_blocklist(target: str) -> None:
    for pat in HARD_BLOCKLIST_PATTERNS:
        if re.match(pat, target.strip()):
            raise UnsafeRequest(
                f"Refusing to scan '{target}': matches an internet-wide / "
                f"always-blocked range. This tool will not scan the entire internet."
            )


def require_authorization(target: str, assume_yes: bool = False) -> AuthDecision:
    """
    Interactive (or CI-friendly) authorization gate. Must be called before
    any scan executes. Raises AuthorizationDenied if the operator declines.
    """
    check_hard_blocklist(target)

    private = _is_private_or_loopback(target)
    scope_note = (
        "Target appears to be a private/loopback address (RFC1918 or localhost)."
        if private
        else "Target appears to be a public/external address or hostname — "
             "extra caution advised."
    )

    if assume_yes:
        return AuthDecision(confirmed=True, target=target, note=scope_note + " [auto-confirmed via --yes]")

    print(AUTH_BANNER)
    print(f"Target: {target}")
    print(scope_note)
    answer = input("Type EXACTLY 'I AM AUTHORIZED' to proceed: ").strip()

    if answer != "I AM AUTHORIZED":
        raise AuthorizationDenied("Authorization phrase not matched. Scan aborted.")

    return AuthDecision(confirmed=True, target=target, note=scope_note)


def guard_dangerous_flags(nmap_args: list[str]) -> list[str]:
    """
    Strip or block flags that are almost never appropriate for an
    intent-driven assistant to auto-select (e.g. flags that could be
    used for aggressive DoS-style timing against fragile hosts, or
    flags that write files outside the sandboxed output dir).
    """
    blocked_substrings = ["--script=dos", "--max-parallelism=0"]
    cleaned = []
    for arg in nmap_args:
        if any(b in arg for b in blocked_substrings):
            print(f"[safety] Dropping disallowed flag: {arg}", file=sys.stderr)
            continue
        cleaned.append(arg)
    return cleaned
