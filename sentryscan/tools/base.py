"""
tools/base.py — Common contract every chained tool adapter implements.

The agent orchestrator only ever talks to this interface. Adding a new
tool to the chain means writing one adapter class here — the decision
engine and reporting pipeline don't need to change.
"""

from dataclasses import dataclass, field
from typing import Optional
import shutil


@dataclass
class Finding:
    """One atomic piece of information a tool discovered."""
    tool: str
    host: str
    port: Optional[int]
    category: str          # e.g. "web-tech", "tls", "smb-share", "banner", "vuln-hint"
    summary: str
    severity: str = "info"  # info | medium | high
    raw: str = ""


@dataclass
class ToolRunResult:
    tool_name: str
    ran: bool
    skipped_reason: str = ""
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""


class ToolAdapter:
    """Base class for a chainable recon tool."""

    name: str = "base"
    requires_binary: Optional[str] = None  # e.g. "nikto"; None if pure-python

    def is_available(self) -> bool:
        if self.requires_binary is None:
            return True
        return shutil.which(self.requires_binary) is not None

    def applies_to(self, port: int, service: str) -> bool:
        """Whether this adapter should run against a given open port/service."""
        raise NotImplementedError

    def run(self, host: str, port: int, service: str, timeout: int = 60) -> ToolRunResult:
        raise NotImplementedError
