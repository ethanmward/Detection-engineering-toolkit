"""
MITRE ATT&CK Detection Coverage Analyzer
Maps deployed detection rules to the ATT&CK framework and identifies coverage gaps.
Outputs a prioritized gap report and visual heatmap.

Author: Ethan Ward
Version: 1.0
"""

import json
import os
import re
import sys
import argparse
from pathlib import Path
from collections import defaultdict
from datetime import datetime


# MITRE ATT&CK Enterprise Techniques (subset — extend as needed)
ATTACK_MATRIX = {
    "Initial Access": {
        "T1078": "Valid Accounts",
        "T1078.001": "Valid Accounts: Default Accounts",
        "T1078.002": "Valid Accounts: Domain Accounts",
        "T1078.003": "Valid Accounts: Local Accounts",
        "T1078.004": "Valid Accounts: Cloud Accounts",
        "T1566": "Phishing",
        "T1566.001": "Phishing: Spearphishing Attachment",
        "T1566.002": "Phishing: Spearphishing Link",
        "T1190": "Exploit Public-Facing Application",
    },
    "Execution": {
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
        "T1059.003": "Windows Command Shell",
        "T1059.005": "Visual Basic",
        "T1059.007": "JavaScript",
        "T1204": "User Execution",
        "T1047": "Windows Management Instrumentation",
    },
    "Persistence": {
        "T1053": "Scheduled Task/Job",
        "T1053.005": "Scheduled Task",
        "T1176": "Browser Extensions",
        "T1547": "Boot or Logon Autostart Execution",
        "T1547.001": "Registry Run Keys / Startup Folder",
        "T1136": "Create Account",
        "T1098": "Account Manipulation",
    },
    "Privilege Escalation": {
        "T1548": "Abuse Elevation Control Mechanism",
        "T1548.002": "Bypass User Account Control",
        "T1134": "Access Token Manipulation",
    },
    "Defense Evasion": {
        "T1112": "Modify Registry",
        "T1070": "Indicator Removal",
        "T1070.004": "File Deletion",
        "T1027": "Obfuscated Files or Information",
        "T1218": "System Binary Proxy Execution",
        "T1218.005": "Mshta",
        "T1218.010": "Regsvr32",
        "T1218.011": "Rundll32",
    },
    "Credential Access": {
        "T1110": "Brute Force",
        "T1110.001": "Password Guessing",
        "T1110.003": "Password Spraying",
        "T1110.004": "Credential Stuffing",
        "T1556": "Modify Authentication Process",
        "T1556.006": "Multi-Factor Authentication",
        "T1558": "Steal or Forge Kerberos Tickets",
        "T1558.003": "Kerberoasting",
    },
    "Discovery": {
        "T1087": "Account Discovery",
        "T1087.002": "Domain Account",
        "T1018": "Remote System Discovery",
        "T1082": "System Information Discovery",
        "T1069": "Permission Groups Discovery",
    },
    "Lateral Movement": {
        "T1021": "Remote Services",
        "T1021.001": "Remote Desktop Protocol",
        "T1021.006": "Windows Remote Management",
    },
    "Collection": {
        "T1074": "Data Staged",
        "T1530": "Data from Cloud Storage",
        "T1213": "Data from Information Repositories",
        "T1213.002": "Sharepoint",
    },
    "Exfiltration": {
        "T1567": "Exfiltration Over Web Service",
        "T1567.002": "Exfiltration to Cloud Storage",
        "T1048": "Exfiltration Over Alternative Protocol",
    },
}


def parse_detection_file(filepath: Path) -> dict:
    """Parse a CQL detection file and extract MITRE mappings and metadata."""
    content = filepath.read_text(encoding="utf-8")

    detection = {
        "file": str(filepath),
        "name": "",
        "techniques": [],
        "severity": "UNKNOWN",
        "author": "",
        "version": "",
    }

    # Extract Ward Script header fields
    name_match = re.search(r"Ward Script - (.+)", content)
    if name_match:
        detection["name"] = name_match.group(1).strip()

    # Extract MITRE technique IDs (T followed by 4 digits, optional sub-technique)
    techniques = re.findall(r"T\d{4}(?:\.\d{3})?", content)
    detection["techniques"] = list(set(techniques))

    # Extract severity
    severity_match = re.search(r"Severity:\s*(Critical|High|Medium|Low)", content, re.IGNORECASE)
    if severity_match:
        detection["severity"] = severity_match.group(1).upper()

    # Extract author
    author_match = re.search(r"Author:\s*(.+?)(?:\s*\||\s*$)", content, re.MULTILINE)
    if author_match:
        detection["author"] = author_match.group(1).strip()

    # Extract version
    version_match = re.search(r"v(\d+\.\d+)", content)
    if version_match:
        detection["version"] = version_match.group(1)

    return detection


def scan_detections(detections_dir: Path) -> list:
    """Scan a directory for .cql detection files and parse them all."""
    detections = []
    for cql_file in detections_dir.rglob("*.cql"):
        try:
            detection = parse_detection_file(cql_file)
            if detection["techniques"]:
                detections.append(detection)
        except Exception as e:
            print(f"  [!] Error parsing {cql_file}: {e}")
    return detections


def analyze_coverage(detections: list) -> dict:
    """Analyze detection coverage against MITRE ATT&CK matrix."""
    # Build set of all covered techniques
    covered = set()
    technique_to_detections = defaultdict(list)

    for det in detections:
        for tech in det["techniques"]:
            covered.add(tech)
            technique_to_detections[tech].append(det["name"])

    # Build coverage report
    report = {
        "generated": datetime.now(tz=__import__("datetime").timezone.utc).isoformat() + "Z",
        "total_detections": len(detections),
        "total_techniques_covered": len(covered),
        "total_techniques_in_matrix": sum(len(techs) for techs in ATTACK_MATRIX.values()),
        "coverage_by_tactic": {},
        "gaps": {},
        "covered_techniques": {},
    }

    for tactic, techniques in ATTACK_MATRIX.items():
        tactic_covered = []
        tactic_gaps = []

        for tech_id, tech_name in techniques.items():
            if tech_id in covered:
                tactic_covered.append({
                    "id": tech_id,
                    "name": tech_name,
                    "detections": technique_to_detections[tech_id],
                })
            else:
                tactic_gaps.append({
                    "id": tech_id,
                    "name": tech_name,
                })

        total = len(techniques)
        covered_count = len(tactic_covered)
        coverage_pct = round((covered_count / total) * 100, 1) if total > 0 else 0

        report["coverage_by_tactic"][tactic] = {
            "total": total,
            "covered": covered_count,
            "coverage_percent": coverage_pct,
        }
        report["covered_techniques"][tactic] = tactic_covered
        report["gaps"][tactic] = tactic_gaps

    return report


def prioritize_gaps(report: dict) -> list:
    """Prioritize coverage gaps by tactic importance and prevalence."""
    # Tactics ordered by typical attack chain priority
    tactic_priority = {
        "Initial Access": 10,
        "Execution": 9,
        "Persistence": 9,
        "Privilege Escalation": 8,
        "Defense Evasion": 8,
        "Credential Access": 9,
        "Discovery": 6,
        "Lateral Movement": 8,
        "Collection": 7,
        "Exfiltration": 7,
    }

    prioritized = []
    for tactic, gaps in report["gaps"].items():
        priority = tactic_priority.get(tactic, 5)
        for gap in gaps:
            prioritized.append({
                "technique_id": gap["id"],
                "technique_name": gap["name"],
                "tactic": tactic,
                "priority_score": priority,
            })

    prioritized.sort(key=lambda x: x["priority_score"], reverse=True)
    return prioritized


def render_heatmap(report: dict) -> str:
    """Render an ASCII heatmap of MITRE coverage by tactic."""
    lines = []
    lines.append("")
    lines.append("=" * 70)
    lines.append("  MITRE ATT&CK DETECTION COVERAGE HEATMAP")
    lines.append("=" * 70)
    lines.append("")

    for tactic, stats in report["coverage_by_tactic"].items():
        pct = stats["coverage_percent"]
        covered = stats["covered"]
        total = stats["total"]

        # Visual bar
        bar_width = 30
        filled = int((pct / 100) * bar_width)
        bar = "█" * filled + "░" * (bar_width - filled)

        # Color indicator
        if pct >= 75:
            indicator = "✓"
        elif pct >= 50:
            indicator = "◐"
        elif pct >= 25:
            indicator = "◔"
        else:
            indicator = "✗"

        lines.append(f"  {indicator} {tactic:<24} {bar} {pct:>5.1f}% ({covered}/{total})")

    lines.append("")
    lines.append("  Legend: ✓ 75%+  ◐ 50-74%  ◔ 25-49%  ✗ <25%")
    lines.append("=" * 70)
    return "\n".join(lines)


def render_gap_report(prioritized_gaps: list) -> str:
    """Render a prioritized gap report."""
    lines = []
    lines.append("")
    lines.append("=" * 70)
    lines.append("  PRIORITIZED DETECTION GAPS")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"  {'Priority':<10} {'Technique':<16} {'Name':<30} {'Tactic'}")
    lines.append(f"  {'--------':<10} {'---------':<16} {'----':<30} {'------'}")

    for gap in prioritized_gaps[:20]:  # Top 20 gaps
        priority_label = {10: "CRITICAL", 9: "HIGH", 8: "MEDIUM", 7: "LOW"}.get(
            gap["priority_score"], "INFO"
        )
        lines.append(
            f"  {priority_label:<10} {gap['technique_id']:<16} "
            f"{gap['technique_name']:<30} {gap['tactic']}"
        )

    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Detection Coverage Analyzer"
    )
    parser.add_argument(
        "--detections-dir",
        type=str,
        default="./detections",
        help="Path to directory containing .cql detection files",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./reports",
        help="Output directory for coverage reports",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text", "both"],
        default="both",
        help="Output format",
    )
    args = parser.parse_args()

    detections_dir = Path(args.detections_dir)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n[*] MITRE ATT&CK Detection Coverage Analyzer")
    print(f"[*] Scanning: {detections_dir}")
    print()

    # Scan and parse detections
    detections = scan_detections(detections_dir)
    print(f"[+] Found {len(detections)} detection rules")

    # Analyze coverage
    report = analyze_coverage(detections)
    print(f"[+] Techniques covered: {report['total_techniques_covered']}/{report['total_techniques_in_matrix']}")

    # Prioritize gaps
    prioritized_gaps = prioritize_gaps(report)

    # Render outputs
    heatmap = render_heatmap(report)
    gap_report = render_gap_report(prioritized_gaps)

    print(heatmap)
    print(gap_report)

    # Save outputs
    if args.format in ("json", "both"):
        json_path = output_dir / "coverage_report.json"
        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] JSON report saved: {json_path}")

    if args.format in ("text", "both"):
        text_path = output_dir / "coverage_report.txt"
        with open(text_path, "w") as f:
            f.write(heatmap)
            f.write("\n")
            f.write(gap_report)
            f.write("\n\n--- Detection Inventory ---\n\n")
            for det in detections:
                f.write(f"  {det['name']}\n")
                f.write(f"    File: {det['file']}\n")
                f.write(f"    Techniques: {', '.join(det['techniques'])}\n")
                f.write(f"    Severity: {det['severity']}\n")
                f.write(f"    Version: {det['version']}\n\n")
        print(f"[+] Text report saved: {text_path}")

    # Save prioritized gaps as JSON
    gaps_path = output_dir / "prioritized_gaps.json"
    with open(gaps_path, "w") as f:
        json.dump(prioritized_gaps, f, indent=2)
    print(f"[+] Gap priorities saved: {gaps_path}")

    print("\n[*] Done.\n")


if __name__ == "__main__":
    main()
