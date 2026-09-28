# SentryScan

**An autonomous recon agent: tell it a target in plain English. It runs Nmap, looks at what came back, and automatically chains the right follow-up tools — TLS inspection, HTTP header/tech checks, anonymous FTP/SMB checks, banner grabs, and (opt-in) directory brute-forcing — into one combined report. No manual flag configuration, no manually deciding "ok now I run nikto, now smbclient."**

> Think "Nmap for the AI era, with a brain attached": the LLM never touches your network directly and never invents commands. It only fills in a strict, typed schema (`ScanIntent`), and separately, a deterministic **decision engine** (`agent.py`) maps discovered ports to a fixed, pre-approved set of tool adapters. The model can help parse your sentence and annotate results afterward — it never gets to choose which binary runs.

---

## Why this design (and why it's safe)

Most "AI + nmap" demos just let an LLM generate a shell command and run it — which means prompt injection, hallucinated flags, or a malicious scan target can slip straight into `subprocess`. An *agent* that auto-chains tools raises the stakes further (now it's deciding to run several tools unattended), so SentryScan is built around four hard boundaries:

1. **Structured contract, not free text.** The NLP layer (rule-based by default, optionally LLM-assisted) only ever produces a `ScanIntent` dataclass with a fixed set of typed fields. A single dedicated function (`intent_to_nmap_args`) is the *only* code that turns intent into real flags.
2. **Fixed adapter registry, not open-ended tool invention.** The agent's "decision engine" (`agent.plan_chain`) can only select from a small, pre-written, pre-approved set of `ToolAdapter` classes (`sentryscan/tools/`). It maps `open port -> which adapters apply`, nothing more — it cannot write a new command or call something outside the registry, LLM-assisted or not.
3. **Authorization gate before any packet leaves the machine.** `safety.py` requires an explicit typed confirmation (`"I AM AUTHORIZED"`), warns on public/external targets, and hard-blocks internet-wide ranges — checked once, up front, covering the entire chain, not per-tool.
4. **Intrusiveness tiers.** Read-only/low-noise checks (banner grabs, TLS cert inspection, anonymous-login checks, header analysis, `nikto`/`whatweb` if installed) auto-chain by default. Anything noisy/brute-force (directory brute-forcing via `gobuster`) is a separate `deep` tier that never runs unless you pass `--deep` explicitly.
5. **Read-only AI summarization.** Any LLM call in the reporting stage only ever receives *already-completed* findings as text — it has no tool access and cannot trigger another scan.

```
 "recon 10.0.0.5,          ┌────────────────┐     ┌────────────┐     ┌──────────────┐
  it's a web server"  ---> │ Intent Parser  │ --> │  Safety /  │ --> │  Nmap (port   │
                            │ (rules + LLM)  │     │  Auth Gate │     │  discovery)   │
                            └────────────────┘     └────────────┘     └──────┬───────┘
                                                                              │ open ports
                                                                              ▼
                                                                    ┌──────────────────┐
                                                                    │  Decision Engine   │
                                                                    │  (agent.plan_chain)│
                                                                    │  port -> adapters  │
                                                                    └─────────┬──────────┘
                                                                              │ fixed, pre-approved
                                                    ┌─────────────┬───────────┼───────────┬─────────────┐
                                                    ▼             ▼           ▼           ▼             ▼
                                                TLS inspect   HTTP headers  FTP-anon   SMB list    whatweb/nikto
                                                (pure python) (pure python) (pure py)  (smbclient)  (if installed)
                                                    │             │           │           │             │
                                                    └─────────────┴───────────┴───────────┴─────────────┘
                                                                              │
                                                                              ▼
                                                                 ┌─────────────────────────┐
                                                                 │ Risk Rules + Combined     │
                                                                 │ Report (+ optional AI     │
                                                                 │ triage notes, read-only)  │
                                                                 └─────────────────────────┘
```

## Features

- **Natural-language intent parsing** — targets, port scope, scan intensity, OS/script/UDP flags all inferred from a sentence; optional LLM-assisted parsing for ambiguous requests.
- **Autonomous tool chaining (`agent` mode)** — after Nmap finds open ports, a deterministic decision engine automatically runs the right follow-up checks per port/service:
  | Port(s) | Chained adapter | What it does |
  |---|---|---|
  | 80/8080/8000/8888 | `http-headers` (pure Python) | Server/tech headers, missing security-header check |
  | 443/8443/465/993/995 | `tls-inspect` (pure Python) | Real TLS handshake → cert subject/issuer/expiry, weak/expired cert flagging |
  | 21 | `ftp-anon-check` (pure Python) | Checks if anonymous FTP login is accepted (read-only, no file listing) |
  | 21/22/25/110/143/3306/5432/6379/27017/9200 | `banner-grab` (pure Python) | Raw service banner |
  | 139/445 | `smbclient` *(if installed)* | Anonymous SMB share listing check |
  | 80/443/8080/8443 | `whatweb`, `nikto` *(if installed)* | Web tech fingerprinting, common misconfig/vuln hints |
  | 80/443/8080/8443 | `gobuster` *(opt-in `--deep` only)* | Directory brute-forcing |
- **Graceful degradation** — any adapter whose binary isn't installed is skipped with a clear reason, never a crash.
- **Deterministic offline risk heuristics** — flags common high-risk exposures (open SMB, Redis/Mongo default-no-auth history, RDP, Telnet, oversized attack surface) with zero API calls required.
- **Optional AI triage notes** — read-only ranking of "what to look at first" across all chained findings.
- **Safety-first execution** — one authorization gate covers the whole chain, hard-blocked internet-wide ranges, strict argv everywhere (never shell-interpolated).
- **Dry-run mode** — preview the intent, the nmap command, and the full adapter registry before anything executes.

## Installation

```bash
# 1. Install nmap itself
sudo apt install nmap        # Debian/Ubuntu
brew install nmap            # macOS

# 2. Install SentryScan
git clone <this-repo>
cd sentryscan
pip install -e .

# 3. (Optional) enable AI-assisted parsing + summaries
export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

### Agent mode (recommended) — full autonomous chain

```bash
# Full flow: nmap -> decision engine -> chained tools -> combined report
sentryscan agent "recon 192.168.1.10, it's a web server"

# Preview the plan only (parsed intent + nmap command + adapter registry), nothing executed
sentryscan agent "recon my-test-server.local" --dry-run

# Also allow intrusive tools (directory brute-forcing), opt-in only
sentryscan agent "thoroughly check 10.0.0.5" --deep --yes

# CI/non-interactive (only when authorization is controlled elsewhere)
sentryscan agent "check 10.0.0.5 for misconfigurations" --yes

# Save the combined report
sentryscan agent "recon 10.0.0.0/24" --out report.txt
```

### Scan mode — single Nmap pass, no chaining

```bash
sentryscan scan "quick check if 10.0.0.5 has any open ports" --yes
```

### Example agent session

```
$ sentryscan agent "recon 10.0.0.5, it's probably a web server" --yes

Parsed intent -> nmap -sT -p 80,443,8080,8443,8000,8888 -sV -T3 -oX - 10.0.0.5
...authorization prompt...

Planned follow-up actions:
  - banner-grab      -> 10.0.0.5:443 (https)
  - tls-inspect       -> 10.0.0.5:443 (https)
  - http-headers      -> 10.0.0.5:80 (http)
  - whatweb           -> 10.0.0.5:80 (http)   [SKIP: binary not installed]

[agent] Running banner-grab against 10.0.0.5:443 ...
[agent] Running tls-inspect against 10.0.0.5:443 ...
[agent] Running http-headers against 10.0.0.5:80 ...

======================================================================
SentryScan Agent Report
======================================================================
Target request: recon 10.0.0.5, it's probably a web server
Derived from request: port scope='web', intensity='normal'

----------------------------------------------------------------------
Stage 1 — Port Discovery (nmap)
----------------------------------------------------------------------
Host 10.0.0.5 (no hostname) — up
    - 80/tcp  open http nginx 1.18.0
    - 443/tcp open https nginx 1.18.0

----------------------------------------------------------------------
Stage 2 — Chained Tool Execution (3 run, 1 skipped)
----------------------------------------------------------------------
  ✔ banner-grab      10.0.0.5:443  (1 finding)
  ✔ tls-inspect       10.0.0.5:443  (1 finding)
  ✔ http-headers      10.0.0.5:80   (2 findings)
  ⏭ whatweb           10.0.0.5:80   skipped — 'whatweb' not installed

----------------------------------------------------------------------
Stage 3 — Findings
----------------------------------------------------------------------
  🟠 [MEDIUM] http-headers @ 10.0.0.5:80 (vuln-hint) — Missing security headers: Content-Security-Policy, X-Frame-Options
  🔵 [INFO] tls-inspect @ 10.0.0.5:443 (tls) — Cert CN=10.0.0.5 issuer=Internal-CA expires=Jan 1 00:00:00 2027 GMT
  🔵 [INFO] http-headers @ 10.0.0.5:80 (web-tech) — HTTP 200 — Server: nginx/1.18.0
```

Adding a new chained tool means writing one `ToolAdapter` subclass in `sentryscan/tools/` and registering it — the agent's decision engine, execution loop, and reporting all pick it up automatically.

## Project layout

```
sentryscan/
├── sentryscan/
│   ├── intent_parser.py   # NL -> ScanIntent -> nmap argv (the only place nmap flags are built)
│   ├── safety.py          # authorization gate, hard blocklist, dangerous-flag stripping
│   ├── scanner.py         # subprocess wrapper around nmap (strict argv, never shell=True)
│   ├── result_parser.py   # nmap XML -> typed ScanReport/HostResult/PortResult
│   ├── risk_rules.py      # offline heuristics for common risky exposures
│   ├── summarizer.py      # template + optional AI narrative summary (scan mode)
│   ├── agent.py           # decision engine: open ports -> which adapters run, execution loop
│   ├── agent_report.py    # renders a full AgentRun into a combined report
│   ├── tools/
│   │   ├── base.py             # ToolAdapter interface + Finding schema
│   │   ├── native_probes.py    # pure-Python adapters: banner grab, TLS inspect, FTP-anon, HTTP headers
│   │   └── external_tools.py   # optional-binary adapters: whatweb, nikto, smbclient, gobuster (deep-tier)
│   └── cli.py              # entrypoint: `sentryscan agent ...` / `sentryscan scan ...`
├── tests/
│   ├── test_core.py        # intent parsing + risk rules (offline)
│   └── test_agent.py       # decision engine chaining logic (offline)
├── setup.py
└── requirements.txt
```

## Legal / responsible use

Only scan systems you own or are explicitly authorized in writing to test. Unauthorized scanning can violate laws such as the U.S. Computer Fraud and Abuse Act or the UK Computer Misuse Act. SentryScan's authorization prompt is a safeguard, not a legal shield — you are responsible for how you use it.

## Roadmap ideas

- Plug-in architecture for other scanners (masscan, rustscan) behind the same `ScanIntent` contract
- Historical diffing ("what changed since last week's scan")
- Structured JSON export for SIEM ingestion
- Local model support (Ollama) as an alternative to the Anthropic API for fully offline AI parsing/summaries
