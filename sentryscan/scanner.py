"""
scanner.py — Executes Nmap as a subprocess (never via shell=True, never
via string interpolation) and returns raw XML for structured parsing.
"""

import shutil
import subprocess
import sys
from dataclasses import dataclass

from .safety import guard_dangerous_flags


class NmapNotFound(Exception):
    pass


class ScanFailed(Exception):
    pass


@dataclass
class ScanResult:
    target: str
    args: list[str]
    xml_output: str
    returncode: int


def ensure_nmap_available() -> str:
    path = shutil.which("nmap")
    if not path:
        raise NmapNotFound(
            "nmap binary not found on PATH. Install it first:\n"
            "  Debian/Ubuntu: sudo apt install nmap\n"
            "  macOS:         brew install nmap\n"
            "  Windows:       https://nmap.org/download.html"
        )
    return path


def run_scan(target: str, nmap_args: list[str], timeout_sec: int = 900) -> ScanResult:
    """
    Runs nmap with a strict argument list (no shell string). Target is
    passed as its own argv element, never concatenated into a flag.
    """
    nmap_path = ensure_nmap_available()
    safe_args = guard_dangerous_flags(nmap_args)
    cmd = [nmap_path, *safe_args, target]

    print(f"[scanner] Executing: {' '.join(cmd)}", file=sys.stderr)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise ScanFailed(f"Scan timed out after {timeout_sec}s: {e}")
    except PermissionError:
        raise ScanFailed(
            "Permission denied running nmap. SYN scan (-sS) and OS detection "
            "(-O) require root/administrator privileges. Re-run with sudo, "
            "or let SentryScan fall back to a TCP connect scan."
        )

    if proc.returncode != 0 and not proc.stdout.strip():
        raise ScanFailed(f"nmap exited {proc.returncode}: {proc.stderr.strip()}")

    return ScanResult(target=target, args=safe_args, xml_output=proc.stdout, returncode=proc.returncode)
