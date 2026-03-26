# 🔍 sysmon-config-analyser

> Parse Sysmon XML configuration files and automatically flag detection gaps, missing high-priority event IDs, and potential evasion surfaces.

Built from first-hand research into Sysmon's kernel event pipeline during a cybersecurity research attachment at MINDEF, Singapore.

---

## Why This Exists

Sysmon is one of the most widely deployed host-based monitoring tools in enterprise defence — but a poorly written config can leave massive blind spots. During my research into Sysmon internals (kernel callbacks → ETW → minifilter drivers → EVTX), I noticed that configuration quality varies wildly and that detection gaps are rarely surfaced automatically.

This tool gives defenders a fast way to audit their Sysmon configs before attackers exploit the gaps.

---

## Features

- ✅ Parses any Sysmon XML config file
- 🚨 Flags **missing high-priority event IDs** (process injection, LSASS access, driver loads, DNS queries, etc.)
- ⚠️ Detects **overly broad exclusion rules** that could suppress legitimate detections
- 🔐 Checks for **LSASS-specific monitoring** gaps (credential dumping surface)
- 📊 Coloured terminal report with CRITICAL / WARNING / INFO severity levels
- 📁 Optional **JSON export** for integration with SIEM pipelines or reporting tools

---

## Installation

```bash
git clone https://github.com/yeelaiii/sysmon-config-analyser
cd sysmon-config-analyser
python3 sysmon_analyser.py --help
```

No external dependencies — pure Python 3 stdlib only.

---

## Usage

```bash
# Basic analysis
python3 sysmon_analyser.py sysmonconfig.xml

# Export findings to JSON
python3 sysmon_analyser.py sysmonconfig.xml --json report.json

# Quiet mode (JSON only, no terminal output)
python3 sysmon_analyser.py sysmonconfig.xml --json report.json --quiet
```

---

## Sample Output

```
────────────────────────────────────────────────────────────
  Sysmon Config Analyser — github.com/yeelaiii
────────────────────────────────────────────────────────────
  Config     : sysmonconfig.xml
  Schema     : 4.82
  Configured events : [1, 3, 7, 11, 22]
────────────────────────────────────────────────────────────

  CRITICAL: 4   WARNING: 2   INFO: 0

  [CRITICAL] [Event 6] Missing high-priority event: DriverLoad (ID 6)
             Driver loaded — kernel rootkit detection. No rule configured — completely unmonitored.

  [CRITICAL] [Event 8] Missing high-priority event: CreateRemoteThread (ID 8)
             Remote thread creation — injection. No rule configured — completely unmonitored.

  [WARNING] ProcessAccess: No explicit LSASS monitoring rule
            LSASS process access is a key indicator of credential dumping.
```

---

## Covered Event IDs

| ID | Event | Priority | Why It Matters |
|----|-------|----------|----------------|
| 1  | ProcessCreate | HIGH | Core execution telemetry |
| 6  | DriverLoad | HIGH | Kernel rootkit detection |
| 8  | CreateRemoteThread | HIGH | Process injection |
| 9  | RawAccessRead | HIGH | Credential dumping |
| 10 | ProcessAccess | HIGH | LSASS / memory access |
| 19-21 | WmiEvent | HIGH | WMI persistence |
| 22 | DNSEvent | HIGH | C2 beacon detection |
| 25 | ProcessTampering | HIGH | Hollowing / herpaderping |
| ... | | | |

---

## Background Research

This tool is informed by my research into Sysmon's internal architecture:

- Kernel callback registration and ETW provider enumeration
- Minifilter driver behaviour and filter attachment order
- Configuration filtering logic and bypass surface evaluation
- Full event pipeline: kernel trigger → user-mode service → EVTX

Findings from this research were presented to senior stakeholders at the Ministry of Defence, Singapore.

---

## Roadmap

- [ ] Severity scoring / overall config health score
- [ ] Comparison mode (diff two configs)
- [ ] Recommended rule suggestions for missing events
- [ ] HTML report export
- [ ] Integration with SwiftOnSecurity config baseline

---

## Author

**Elijah Soon** · [yeelaiii.github.io](https://yeelaiii.github.io) · [LinkedIn](https://www.linkedin.com/in/elijahsoon)

SUTD Year 3 · CS & Design · CCNA · OSCP (prep)
