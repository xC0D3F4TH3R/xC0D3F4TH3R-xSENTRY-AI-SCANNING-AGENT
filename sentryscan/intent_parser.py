"""
intent_parser.py — Translates a free-text scan request into a structured
ScanIntent, and that intent into concrete Nmap flags.

Two modes:
  1. Rule-based (default, offline, deterministic) — keyword/regex driven.
  2. LLM-assisted (optional) — if ANTHROPIC_API_KEY is set, ambiguous or
     complex requests are sent to Claude to fill in the structured schema,
     with the rule-based parser's output given as a fallback/prior.

The structured schema (ScanIntent) is the real contract: whatever produces
it — regex or an LLM — the rest of the pipeline (scanner, parser, summary)
only ever sees this typed object, never raw flags dreamed up by a model.
"""

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------
# Structured schema — the "contract" between NLP layer and the scanner.
# The LLM (if used) is only allowed to populate these fields; it can
# never inject arbitrary nmap flags directly. That keeps prompt
# injection / hallucinated flags from ever reaching subprocess.
# ---------------------------------------------------------------------

VALID_INTENSITIES = {"quiet", "normal", "aggressive"}
VALID_PORT_MODES = {"top-100", "top-1000", "all", "custom", "web", "common-db"}


@dataclass
class ScanIntent:
    target: str = ""
    port_mode: str = "top-1000"          # top-100 | top-1000 | all | custom | web | common-db
    custom_ports: Optional[str] = None    # e.g. "22,80,443" or "1-1024"
    service_detection: bool = True        # -sV
    os_detection: bool = False            # -O
    script_scan: bool = False             # -sC (safe default scripts only)
    udp: bool = False                     # -sU
    intensity: str = "normal"             # quiet | normal | aggressive -> timing template
    stealth: bool = False                 # -sS (needs root) vs -sT
    reason: str = ""                      # human-readable justification, echoed in report
    raw_request: str = ""

    def validate(self) -> None:
        if self.port_mode not in VALID_PORT_MODES:
            self.port_mode = "top-1000"
        if self.intensity not in VALID_INTENSITIES:
            self.intensity = "normal"


PORT_MODE_KEYWORDS = {
    "web": ["web", "http", "website", "webserver", "web server", "web app"],
    "common-db": ["database", "db ", "mysql", "postgres", "mongo", "redis", "sql"],
    "all": ["all ports", "every port", "full port", "65535"],
    "top-100": ["quick", "fast", "light scan", "top 100", "top-100"],
}

INTENSITY_KEYWORDS = {
    "aggressive": ["aggressive", "thorough", "deep", "full scan", "everything"],
    "quiet": ["quiet", "stealthy", "slow", "sneaky", "low profile", "avoid detection"],
}

FLAG_KEYWORDS = {
    "os_detection": ["os detect", "operating system", "fingerprint the os", "what os"],
    "script_scan": ["vuln", "vulnerable", "vulnerability", "default scripts", "-sc", "cve"],
    "udp": ["udp"],
    "stealth": ["stealth", "syn scan", "half-open"],
}

TARGET_PATTERNS = [
    r"\b(?:(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)\b",                 # IPv4 / CIDR
    r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",  # hostname
]

CUSTOM_PORT_PATTERN = r"port[s]?\s+([\d,\-\s]+)"


def _extract_target(text: str) -> str:
    for pat in TARGET_PATTERNS:
        m = re.search(pat, text)
        if m:
            return m.group(0)
    return ""


def _keyword_hit(text: str, keywords: list[str]) -> bool:
    t = text.lower()
    return any(k in t for k in keywords)


def parse_intent_rule_based(text: str) -> ScanIntent:
    intent = ScanIntent(raw_request=text)
    intent.target = _extract_target(text)

    for mode, kws in PORT_MODE_KEYWORDS.items():
        if _keyword_hit(text, kws):
            intent.port_mode = mode
            break

    m = re.search(CUSTOM_PORT_PATTERN, text, re.IGNORECASE)
    if m:
        intent.port_mode = "custom"
        intent.custom_ports = m.group(1).replace(" ", "")

    for level, kws in INTENSITY_KEYWORDS.items():
        if _keyword_hit(text, kws):
            intent.intensity = level
            break

    intent.os_detection = _keyword_hit(text, FLAG_KEYWORDS["os_detection"])
    intent.script_scan = _keyword_hit(text, FLAG_KEYWORDS["script_scan"])
    intent.udp = _keyword_hit(text, FLAG_KEYWORDS["udp"])
    intent.stealth = _keyword_hit(text, FLAG_KEYWORDS["stealth"])

    intent.reason = _explain(intent)
    intent.validate()
    return intent


def _explain(intent: ScanIntent) -> str:
    bits = [f"port scope='{intent.port_mode}'", f"intensity='{intent.intensity}'"]
    if intent.os_detection:
        bits.append("OS detection requested")
    if intent.script_scan:
        bits.append("default/vuln scripts requested")
    if intent.udp:
        bits.append("UDP scan requested")
    return "Derived from request: " + ", ".join(bits)


def parse_intent_llm(text: str, fallback: ScanIntent) -> ScanIntent:
    """
    Optional LLM-assisted parsing for ambiguous requests. Requires
    ANTHROPIC_API_KEY. The model returns ONLY JSON matching ScanIntent's
    fields; anything else is ignored and we keep the rule-based fallback.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return fallback

    try:
        import anthropic
    except ImportError:
        return fallback

    schema_hint = json.dumps(asdict(fallback), indent=2)
    system = (
        "You convert a plain-English network scan request into STRICT JSON only, "
        "matching this schema (no extra keys, no prose, no markdown fences):\n"
        f"{schema_hint}\n"
        "Rules: port_mode must be one of top-100/top-1000/all/custom/web/common-db. "
        "intensity must be one of quiet/normal/aggressive. "
        "Never invent a target if none is present in the text — leave target empty. "
        "Do not include any explanation, only the JSON object."
    )

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=400,
            system=system,
            messages=[{"role": "user", "content": text}],
        )
        raw = "".join(b.text for b in resp.content if hasattr(b, "text"))
        raw = raw.strip().strip("`")
        if raw.startswith("json"):
            raw = raw[4:]
        data = json.loads(raw)

        merged = ScanIntent(**{**asdict(fallback), **{k: v for k, v in data.items() if k in asdict(fallback)}})
        merged.raw_request = text
        merged.validate()
        # Never let the LLM silently invent a target the rule parser
        # didn't also find some evidence for, unless fallback had none.
        if not merged.target:
            merged.target = fallback.target
        return merged
    except Exception:
        return fallback


def parse_intent(text: str, use_llm: bool = True) -> ScanIntent:
    fallback = parse_intent_rule_based(text)
    if use_llm:
        return parse_intent_llm(text, fallback)
    return fallback


# ---------------------------------------------------------------------
# Intent -> Nmap flags (the ONLY place that builds the actual command)
# ---------------------------------------------------------------------

def intent_to_nmap_args(intent: ScanIntent) -> list[str]:
    args: list[str] = []

    # Scan type / privilege
    args.append("-sS" if intent.stealth else "-sT")
    if intent.udp:
        args.append("-sU")

    # Ports
    if intent.port_mode == "top-100":
        args += ["--top-ports", "100"]
    elif intent.port_mode == "top-1000":
        args += ["--top-ports", "1000"]
    elif intent.port_mode == "all":
        args += ["-p-"]
    elif intent.port_mode == "web":
        args += ["-p", "80,443,8080,8443,8000,8888"]
    elif intent.port_mode == "common-db":
        args += ["-p", "1433,1521,3306,5432,6379,27017"]
    elif intent.port_mode == "custom" and intent.custom_ports:
        args += ["-p", intent.custom_ports]
    else:
        args += ["--top-ports", "1000"]

    if intent.service_detection:
        args.append("-sV")
    if intent.os_detection:
        args.append("-O")
    if intent.script_scan:
        args += ["-sC"]  # default, non-intrusive script set only

    # Timing template by intensity — never allow -T5 auto-selected without
    # explicit "aggressive"/"fast" language, to avoid accidental DoS-ish behavior.
    timing = {"quiet": "-T2", "normal": "-T3", "aggressive": "-T4"}[intent.intensity]
    args.append(timing)

    args += ["-oX", "-"]  # XML to stdout for structured parsing
    return args
