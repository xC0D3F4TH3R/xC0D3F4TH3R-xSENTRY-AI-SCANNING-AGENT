"""
tools/external_tools.py — Adapters around well-known external recon
binaries. Every adapter is a no-op (with a clear skipped_reason) if the
binary isn't installed — the agent degrades gracefully rather than
failing. All commands run via strict argv (never shell=True).

Intrusiveness tiers:
  - "standard": safe to auto-chain by default (banner/version/cert checks)
  - "deep":     opt-in only (directory brute-forcing etc.) — the agent
                only runs these when the operator passes --deep
"""

import subprocess

from .base import ToolAdapter, ToolRunResult, Finding


class WhatWebAdapter(ToolAdapter):
    name = "whatweb"
    requires_binary = "whatweb"
    tier = "standard"
    TARGET_PORTS = {80, 443, 8080, 8443, 8000, 8888}

    def applies_to(self, port: int, service: str) -> bool:
        return port in self.TARGET_PORTS

    def run(self, host: str, port: int, service: str, timeout: int = 30) -> ToolRunResult:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        cmd = ["whatweb", "--no-errors", "-a", "1", url]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except Exception as e:
            return ToolRunResult(tool_name=self.name, ran=False, skipped_reason=str(e))

        out = proc.stdout.strip()
        findings = []
        if out:
            findings.append(Finding(tool=self.name, host=host, port=port, category="web-tech",
                                     summary=out[:300], severity="info", raw=out))
        return ToolRunResult(tool_name=self.name, ran=True, findings=findings, raw_output=out)


class NiktoAdapter(ToolAdapter):
    name = "nikto"
    requires_binary = "nikto"
    tier = "standard"
    TARGET_PORTS = {80, 443, 8080, 8443}

    def applies_to(self, port: int, service: str) -> bool:
        return port in self.TARGET_PORTS

    def run(self, host: str, port: int, service: str, timeout: int = 180) -> ToolRunResult:
        cmd = ["nikto", "-h", host, "-p", str(port), "-Tuning", "1,2,3,5,7", "-maxtime", "150s"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except Exception as e:
            return ToolRunResult(tool_name=self.name, ran=False, skipped_reason=str(e))

        out = proc.stdout
        findings = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("+") and len(line) > 3:
                sev = "medium" if any(k in line.lower() for k in ("outdated", "vulnerable", "xss", "injection")) else "info"
                findings.append(Finding(tool=self.name, host=host, port=port, category="vuln-hint",
                                         summary=line[:250], severity=sev))
        return ToolRunResult(tool_name=self.name, ran=True, findings=findings, raw_output=out)


class GobusterAdapter(ToolAdapter):
    """
    Directory brute-forcing. Classified 'deep' tier — intrusive/noisy by
    nature (thousands of requests), so the agent never auto-chains this
    unless the operator explicitly opts in with --deep.
    """
    name = "gobuster"
    requires_binary = "gobuster"
    tier = "deep"
    TARGET_PORTS = {80, 443, 8080, 8443}
    DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

    def applies_to(self, port: int, service: str) -> bool:
        return port in self.TARGET_PORTS

    def run(self, host: str, port: int, service: str, timeout: int = 120) -> ToolRunResult:
        import os
        if not os.path.exists(self.DEFAULT_WORDLIST):
            return ToolRunResult(tool_name=self.name, ran=False,
                                  skipped_reason=f"Wordlist not found at {self.DEFAULT_WORDLIST}")
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}/"
        cmd = ["gobuster", "dir", "-u", url, "-w", self.DEFAULT_WORDLIST, "-q", "-t", "20"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except Exception as e:
            return ToolRunResult(tool_name=self.name, ran=False, skipped_reason=str(e))

        out = proc.stdout
        findings = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("/"):
                findings.append(Finding(tool=self.name, host=host, port=port, category="web-path",
                                         summary=f"Discovered path: {line[:200]}", severity="info"))
        return ToolRunResult(tool_name=self.name, ran=True, findings=findings, raw_output=out)


class SmbClientAdapter(ToolAdapter):
    name = "smbclient"
    requires_binary = "smbclient"
    tier = "standard"
    TARGET_PORTS = {139, 445}

    def applies_to(self, port: int, service: str) -> bool:
        return port in self.TARGET_PORTS

    def run(self, host: str, port: int, service: str, timeout: int = 30) -> ToolRunResult:
        cmd = ["smbclient", "-L", host, "-N"]  # -N = no password (anonymous listing only)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except Exception as e:
            return ToolRunResult(tool_name=self.name, ran=False, skipped_reason=str(e))

        out = proc.stdout
        findings = []
        if "Sharename" in out:
            findings.append(Finding(tool=self.name, host=host, port=port, category="smb-share",
                                     summary="SMB shares listable without credentials (anonymous session allowed).",
                                     severity="high", raw=out))
        return ToolRunResult(tool_name=self.name, ran=True, findings=findings, raw_output=out)


STANDARD_EXTERNAL_ADAPTERS = [WhatWebAdapter(), NiktoAdapter(), SmbClientAdapter()]
DEEP_EXTERNAL_ADAPTERS = [GobusterAdapter()]
