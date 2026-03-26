#!/usr/bin/env python3
"""
sysmon-config-analyser
======================
A tool to parse Sysmon XML configuration files and flag potential
detection gaps, missing event IDs, and evasion surfaces.

Author: Elijah Soon (github.com/yeelaiii)
"""

import xml.etree.ElementTree as ET
import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────
# Sysmon Event ID reference map
# ─────────────────────────────────────────────
SYSMON_EVENTS = {
    1:  ("ProcessCreate",           "HIGH",   "Process execution — core for detections"),
    2:  ("FileCreateTime",          "MEDIUM", "File creation time change — timestomping"),
    3:  ("NetworkConnect",          "HIGH",   "Outbound network connections"),
    4:  ("SysmonServiceStateChange","LOW",    "Sysmon service state"),
    5:  ("ProcessTerminate",        "LOW",    "Process termination"),
    6:  ("DriverLoad",              "HIGH",   "Driver loaded — kernel rootkit detection"),
    7:  ("ImageLoad",               "MEDIUM", "DLL/image load — DLL hijacking"),
    8:  ("CreateRemoteThread",      "HIGH",   "Remote thread creation — injection"),
    9:  ("RawAccessRead",           "HIGH",   "Raw disk read — credential dumping"),
    10: ("ProcessAccess",           "HIGH",   "Process memory access — LSASS dumping"),
    11: ("FileCreate",              "MEDIUM", "File created"),
    12: ("RegistryObjectCreate",    "MEDIUM", "Registry key/value create/delete"),
    13: ("RegistryValueSet",        "MEDIUM", "Registry value modification"),
    14: ("RegistryKeyRename",       "LOW",    "Registry key rename"),
    15: ("FileCreateStreamHash",    "MEDIUM", "Alternate data stream creation"),
    16: ("ServiceConfigChange",     "LOW",    "Sysmon config change"),
    17: ("PipeEvent",               "MEDIUM", "Named pipe created"),
    18: ("PipeEvent",               "MEDIUM", "Named pipe connected"),
    19: ("WmiEvent",                "HIGH",   "WMI filter — persistence"),
    20: ("WmiEvent",                "HIGH",   "WMI consumer — persistence"),
    21: ("WmiEvent",                "HIGH",   "WMI consumer-to-filter binding"),
    22: ("DNSEvent",                "HIGH",   "DNS query — C2 detection"),
    23: ("FileDelete",              "MEDIUM", "File deletion — evidence removal"),
    24: ("ClipboardChange",         "LOW",    "Clipboard contents captured"),
    25: ("ProcessTampering",        "HIGH",   "Process image hollowing/herpaderping"),
    26: ("FileDeleteDetected",      "MEDIUM", "File delete — blocked by archive"),
    27: ("FileBlockExecutable",     "HIGH",   "Executable file creation blocked"),
    28: ("FileBlockShredding",      "HIGH",   "File shredding blocked"),
    29: ("FileExecutableDetected",  "HIGH",   "Executable file detected in monitored dir"),
}

HIGH_PRIORITY_IDS = {eid for eid, (_, priority, _) in SYSMON_EVENTS.items() if priority == "HIGH"}


@dataclass
class Finding:
    severity: str       # CRITICAL / WARNING / INFO
    event_id: Optional[int]
    title: str
    detail: str


@dataclass
class AnalysisResult:
    config_file: str
    schema_version: Optional[str] = None
    configured_events: list = field(default_factory=list)
    missing_high_priority: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    include_rules: dict = field(default_factory=dict)
    exclude_rules: dict = field(default_factory=dict)


def parse_config(filepath: str) -> AnalysisResult:
    result = AnalysisResult(config_file=filepath)

    try:
        tree = ET.parse(filepath)
    except ET.ParseError as e:
        print(f"[ERROR] Failed to parse XML: {e}", file=sys.stderr)
        sys.exit(1)

    root = tree.getroot()
    result.schema_version = root.attrib.get("schemaversion", "unknown")

    event_filtering = root.find("EventFiltering")
    if event_filtering is None:
        result.findings.append(Finding(
            severity="CRITICAL",
            event_id=None,
            title="No EventFiltering block found",
            detail="The config has no EventFiltering section — Sysmon may log nothing or everything depending on defaults."
        ))
        return result

    configured_event_names = set()

    for rule_group in event_filtering:
        tag = rule_group.tag
        on_match = rule_group.attrib.get("onmatch", "include").lower()

        # Map tag name → event ID
        event_id = next((eid for eid, (name, _, _) in SYSMON_EVENTS.items() if name == tag), None)
        if event_id:
            configured_event_names.add(event_id)
            result.configured_events.append(event_id)

        rules = list(rule_group)
        if not rules and on_match == "include":
            result.findings.append(Finding(
                severity="WARNING",
                event_id=event_id,
                title=f"{tag}: include rule with no conditions",
                detail="An empty include block may log all events of this type — high noise, potential performance impact."
            ))
        elif not rules and on_match == "exclude":
            result.findings.append(Finding(
                severity="INFO",
                event_id=event_id,
                title=f"{tag}: exclude rule with no conditions",
                detail="An empty exclude block means nothing is excluded — all events of this type pass through."
            ))

        # Check for overly broad exclusion conditions
        for rule in rules:
            condition = rule.attrib.get("condition", "is").lower()
            value = rule.text or ""
            field_name = rule.tag

            if on_match == "exclude" and condition in ("contains", "begin with", "end with") and len(value) <= 3:
                result.findings.append(Finding(
                    severity="WARNING",
                    event_id=event_id,
                    title=f"{tag} [{field_name}]: Overly broad exclusion",
                    detail=f"Excluding events where {field_name} {condition} '{value}' is very broad and may suppress legitimate detections."
                ))

    # Check for missing high-priority event IDs
    result.missing_high_priority = [
        eid for eid in HIGH_PRIORITY_IDS if eid not in configured_event_names
    ]

    for eid in result.missing_high_priority:
        name, _, description = SYSMON_EVENTS[eid]
        result.findings.append(Finding(
            severity="CRITICAL",
            event_id=eid,
            title=f"Missing high-priority event: {name} (ID {eid})",
            detail=f"{description}. No rule configured — this event type is completely unmonitored."
        ))

    # Check for ProcessAccess without LSASS protection
    if 10 in configured_event_names:
        lsass_covered = False
        for rule_group in event_filtering:
            if rule_group.tag == "ProcessAccess":
                for rule in rule_group:
                    if rule.tag == "TargetImage" and "lsass" in (rule.text or "").lower():
                        lsass_covered = True
        if not lsass_covered:
            result.findings.append(Finding(
                severity="WARNING",
                event_id=10,
                title="ProcessAccess: No explicit LSASS monitoring rule",
                detail="LSASS process access is a key indicator of credential dumping. Consider adding a TargetImage rule for lsass.exe."
            ))

    return result


def print_report(result: AnalysisResult):
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    severity_colour = {"CRITICAL": RED, "WARNING": YELLOW, "INFO": CYAN}

    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}  Sysmon Config Analyser — github.com/yeelaiii{RESET}")
    print(f"{'─'*60}")
    print(f"  Config     : {result.config_file}")
    print(f"  Schema     : {result.schema_version}")
    print(f"  Configured events : {sorted(result.configured_events)}")
    print(f"{'─'*60}\n")

    if not result.findings:
        print(f"{GREEN}✓ No issues found.{RESET}\n")
        return

    critical = [f for f in result.findings if f.severity == "CRITICAL"]
    warnings = [f for f in result.findings if f.severity == "WARNING"]
    info     = [f for f in result.findings if f.severity == "INFO"]

    print(f"  {RED}CRITICAL: {len(critical)}{RESET}  {YELLOW}WARNING: {len(warnings)}{RESET}  {CYAN}INFO: {len(info)}{RESET}\n")

    for finding in result.findings:
        colour = severity_colour.get(finding.severity, RESET)
        eid_str = f"[Event {finding.event_id}] " if finding.event_id else ""
        print(f"  {colour}[{finding.severity}]{RESET} {eid_str}{BOLD}{finding.title}{RESET}")
        print(f"           {finding.detail}\n")

    if result.missing_high_priority:
        print(f"{'─'*60}")
        print(f"  {BOLD}Unmonitored high-priority events:{RESET}")
        for eid in sorted(result.missing_high_priority):
            name, _, desc = SYSMON_EVENTS[eid]
            print(f"    {RED}✗{RESET} [{eid:02d}] {name} — {desc}")
        print()


def export_json(result: AnalysisResult, outfile: str):
    data = {
        "config_file": result.config_file,
        "schema_version": result.schema_version,
        "configured_events": sorted(result.configured_events),
        "missing_high_priority_events": sorted(result.missing_high_priority),
        "findings": [
            {
                "severity": f.severity,
                "event_id": f.event_id,
                "title": f.title,
                "detail": f.detail,
            }
            for f in result.findings
        ],
        "summary": {
            "critical": sum(1 for f in result.findings if f.severity == "CRITICAL"),
            "warning":  sum(1 for f in result.findings if f.severity == "WARNING"),
            "info":     sum(1 for f in result.findings if f.severity == "INFO"),
        }
    }
    with open(outfile, "w") as fp:
        json.dump(data, fp, indent=2)
    print(f"[+] JSON report saved to {outfile}")


def main():
    parser = argparse.ArgumentParser(
        description="Sysmon Config Analyser — flag detection gaps and evasion surfaces"
    )
    parser.add_argument("config", help="Path to Sysmon XML config file")
    parser.add_argument("--json", metavar="OUTPUT", help="Export findings to JSON file")
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal output")
    args = parser.parse_args()

    result = parse_config(args.config)

    if not args.quiet:
        print_report(result)

    if args.json:
        export_json(result, args.json)


if __name__ == "__main__":
    main()
