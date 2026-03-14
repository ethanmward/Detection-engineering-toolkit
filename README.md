# Detection Engineering Toolkit

A practical detection engineering framework for CrowdStrike Next-Gen SIEM (CQL), featuring production-ready detection rules, Python automation tooling, and threat hunting queries — all mapped to MITRE ATT&CK.

Built by a detection engineer who writes CQL daily, converts Chronicle rules to NG-SIEM, and builds Python pipelines against enterprise security APIs.

---

## What's Inside

### Detection Rules (`/detections`)
Production-grade CQL detection logic across four threat categories:

| Category | Detections | MITRE Coverage |
|----------|-----------|----------------|
| **Identity Threats** | Risky sign-in → MFA manipulation, LDAP recon scoring, brute force correlation | T1078, T1110, T1556 |
| **Impossible Travel** | Haversine-based geo-anomaly with ASN/VPN exclusions, international self-join variant with device fingerprinting | T1078 |
| **Data Exfiltration** | SharePoint bulk download, cloud storage staging, abnormal download volume | T1567, T1530, T1074 |
| **Persistence & Evasion** | UAC bypass via registry, browser hijack artifacts, scheduled task creation from suspicious parents | T1548, T1176, T1053 |

Each detection includes:
- Full CQL query with inline comments
- MITRE ATT&CK mapping (tactic + technique)
- False positive guidance and tuning recommendations
- Severity scoring logic

### Python Tooling (`/python`)

| Tool | Purpose |
|------|---------|
| **`coverage_analyzer`** | Maps your deployed detections against MITRE ATT&CK and identifies gaps. Outputs a heatmap and prioritized gap report. |
| **`hunt_generator`** | Generates CQL hunt queries from MITRE technique IDs or threat intel indicators. Outputs ready-to-paste queries with Ward Script headers. |
| **`enrichment`** | Enriches IP addresses, domains, and user agents against threat intel APIs (AbuseIPDB, VirusTotal, Shodan). Outputs structured JSON for SIEM correlation. |

### Hunting Queries (`/hunting_queries`)
Ready-to-run CQL queries organized by hunt hypothesis:
- Credential access patterns
- Living-off-the-land binary (LOLBin) abuse
- Encoded PowerShell execution
- Anomalous service account behavior
- Lateral movement indicators

### Documentation (`/docs`)
- `CQL_REFERENCE.md` — Complete CQL syntax and function reference for NG-SIEM
- `INVESTIGATION_PLAYBOOK.md` — Step-by-step alert triage methodology with decision framework
- `CHRONICLE_MIGRATION.md` — Field mapping and rule conversion guide from Chronicle (YARA-L) to CQL

---

## Quick Start

### Run the Coverage Analyzer
```bash
pip install -r python/requirements.txt
python python/coverage_analyzer/analyzer.py --detections-dir ./detections --output ./reports
```

### Generate Hunt Queries
```bash
python python/hunt_generator/generator.py --technique T1078 --platform crowdstrike
```

### Use a Detection Rule
Copy any `.cql` file from `/detections` into CrowdStrike NG-SIEM Advanced Event Search. Each rule specifies the required `#repo` and time window recommendations.

---

## Detection Rule Format

Every detection follows a standardized format:

```
// Ward Script - [Detection Name]
// [Description of what this detects and why it matters]
// MITRE: [Technique IDs] | Severity: [Critical/High/Medium/Low] | Author: Ethan Ward | v1.0
// False Positives: [Known FP sources and tuning guidance]
// Required Repo: [repo name] | Recommended Window: [time range]

#repo=<repository>
| <detection logic>
```

---

## MITRE ATT&CK Coverage Map

```
┌─────────────────────────────────────────────────────────────────────┐
│ Initial   │ Execution │ Persist.  │ Priv Esc  │ Def Evas. │ Cred   │
│ Access    │           │           │           │           │ Access │
├───────────┼───────────┼───────────┼───────────┼───────────┼────────┤
│ T1078 ✓   │ T1059 ✓   │ T1053 ✓   │ T1548 ✓   │ T1548 ✓   │ T1110 ✓│
│ Valid     │ Command   │ Scheduled │ Abuse     │ Abuse     │ Brute  │
│ Accounts  │ & Script  │ Task/Job  │ Elevation │ Elevation │ Force  │
├───────────┼───────────┼───────────┼───────────┼───────────┼────────┤
│           │ T1059.001 │ T1176 ✓   │           │ T1112 ✓   │ T1556 ✓│
│           │ PowerShell│ Browser   │           │ Modify    │ Modify │
│           │           │ Extension │           │ Registry  │ Auth   │
├───────────┼───────────┼───────────┼───────────┼───────────┼────────┤
│ Discovery │ Lat. Move │ Collect.  │ Exfil.    │           │        │
├───────────┼───────────┼───────────┼───────────┼───────────┼────────┤
│ T1087 ✓   │ T1021 ✓   │ T1074 ✓   │ T1567 ✓   │           │        │
│ Account   │ Remote    │ Data      │ Exfil     │           │        │
│ Discovery │ Services  │ Staged    │ Over Web  │           │        │
│ T1018 ✓   │           │ T1530 ✓   │           │           │        │
│ Remote    │           │ Data from │           │           │        │
│ System    │           │ Cloud     │           │           │        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Who This Is For

- Detection engineers working in CrowdStrike NG-SIEM
- SOC analysts looking to move into detection engineering
- Teams migrating from Chronicle/Splunk to CrowdStrike
- Anyone who wants production-tested CQL patterns instead of theoretical examples

---

## About

Built by [Ethan Ward](https://linkedin.com/in/ethanmward) — detection engineer focused on identity threats, CrowdStrike NG-SIEM, and Python security automation.

## License

MIT — use it, fork it, build on it.
