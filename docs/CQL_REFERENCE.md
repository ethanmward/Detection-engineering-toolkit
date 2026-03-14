# CQL Reference Guide for CrowdStrike NG-SIEM

A practical reference for writing, debugging, and optimizing queries in CrowdStrike Next-Gen SIEM using CQL (Falcon Query Language). Built from production investigation and detection engineering work.

---

## Core Concepts

**Repositories (`#repo`)**: All data lives in repos. Every query must specify one. Using the wrong repo is the #1 cause of zero results.

**Events**: Individual log entries with key-value fields. The `#event_simpleName` field determines event type in `base_sensor`.

**Time**: Set the time range in the UI time picker. CQL does not support inline timestamp filtering.

---

## Repository Quick Reference

| Repository | Contents | Use Case |
|-----------|----------|----------|
| `base_sensor` | EDR telemetry (process, file, network, registry) | Endpoint investigation, threat hunting |
| `detections` | CrowdStrike alerts and detection events | Alert review, detection tuning |
| `okta` | Okta identity events | Identity investigations |
| `fortinet` | Firewall logs | Network investigations |
| `mimecast` | Email security events | Phishing investigations |
| `microsoft_graphapi` | Graph API / Entra ID events | M365 and identity investigations |

**Discover all repos:**
```
| groupBy([#repo], function=count()) | sort(_count, order=desc)
```

---

## Syntax Essentials

```
#repo=base_sensor                    // Always start with repo
| #event_simpleName=ProcessRollup2   // Filter by event type
| CommandLine=/pattern/i             // Regex (case-insensitive)
| UserName!=/excluded/i              // Negation
| FieldName=*                        // Field exists
| !FieldName=*                       // Field does NOT exist
| groupBy([field], function=count()) // Aggregate
| sort(_count, order=desc)           // Sort results
```

**Critical rules:**
- No inline timestamp filtering — use the UI time picker
- Regex uses `/pattern/i`, not quotes
- Field names are case-sensitive
- `#` prefix = metadata fields, `@` prefix = system fields

---

## Key Process Fields (ProcessRollup2)

| Field | Description | Investigation Use |
|-------|-------------|-------------------|
| `CommandLine` | Full command line | What was executed |
| `ImageFileName` | Full executable path | What binary ran |
| `ParentBaseFileName` | Parent process name | What spawned it |
| `GrandParentBaseFileName` | Grandparent process | Context chain |
| `UserName` | Account that ran it | Human vs machine |
| `ComputerName` | Hostname | Scope of activity |
| `SessionId` | Windows session | 0=service, 1+=interactive |
| `ParentProcessId` | CS internal parent PID | Process tree reconstruction |
| `aid` | Agent ID (unique per sensor) | Pivot to endpoint |

**Key indicators:**
- `UserName` ending in `$` = machine/SYSTEM account
- `GrandParentBaseFileName=explorer.exe` = interactive (RDP/console)
- `GrandParentBaseFileName=services.exe` = service or scheduled task
- `SessionId=0` = SYSTEM context
- `AuthenticationId=999` = SYSTEM logon

---

## Essential Query Patterns

### Process Tree Reconstruction
The single most decisive investigative query:
```
#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ParentProcessId=<PID_FROM_ALERT>
| groupBy([CommandLine, FileName], function=count(), limit=100)
| sort(_count, order=desc)
```

### Environment-Wide TTP Scan
```
#repo=base_sensor
| CommandLine=/suspicious_pattern/i
```
Thousands of hits = likely legitimate. Isolated to 1-2 hosts = investigate.

### User Activity Footprint
```
#repo=base_sensor
| #event_simpleName=ProcessRollup2
| UserName=/suspect_account/i
| groupBy([ComputerName], function=count(), limit=50)
| sort(_count, order=desc)
```

---

## Investigation Methodology

1. **Understand the alert** — What TTP? What host/user? Convert UTC timestamps.
2. **Scope environment-wide** — Is this pattern seen everywhere or isolated?
3. **Identify user and process context** — Human or machine? Interactive or service?
4. **Reconstruct process tree** — This is the most decisive step.
5. **Check account footprint** — Is this account where it should be?
6. **Look for corroborating TTPs** — One indicator is often insufficient.
7. **Check network activity** — DNS and connections from the affected host.
8. **Make a verdict** — Use the decision framework below.

### Verdict Decision Framework

| Finding | Verdict | Action |
|---------|---------|--------|
| Thousands of env-wide hits | FALSE POSITIVE | Close, tune rule |
| Isolated + unknown process tree | NEEDS INVESTIGATION | Continue analysis |
| Process tree = standard admin tools | LEGITIMATE | Close |
| Encoded PS + download cradles | LIKELY MALICIOUS | Escalate |
| Account on known server cluster | EXPECTED | Supports benign |
| Account on random workstations | LATERAL MOVEMENT | Escalate |
| Single TTP, no corroboration | FALSE POSITIVE | Close |
| Multiple TTPs from same rule | TRUE POSITIVE | Escalate |

---

## Function Quick Reference

| Function | Example |
|----------|---------|
| `groupBy()` | `groupBy([field], function=count(), limit=50)` |
| `sort()` | `sort(_count, order=desc)` |
| `select()` | `select([@timestamp, ComputerName, CommandLine])` |
| `head()` / `tail()` | `head(10)` |
| `rename()` | `rename(field=src, as=source)` |
| `case{}` | `score:=case { field=/HIGH/i => 400; * => 100; }` |
| `selfJoinFilter()` | `selfJoinFilter(field=user, where=[{a=x},{b=y}])` |
| `ioc:lookup()` | `ioc:lookup(field=ip, type=ip_address)` |
| `in()` | `in(status, values=["500","404"])` |

---

## Common Gotchas

1. **Wrong repo**: `base_sensor` for EDR, not `falcon-raw-data`
2. **Inline time filtering**: Does not work — use UI time picker
3. **Case sensitivity**: `CommandLine` works, `commandline` may not
4. **ParentProcessId**: CrowdStrike internal ID, NOT Windows PID
5. **Machine accounts**: `UserName$` = SYSTEM, not a human
6. **Azure Guest Config**: `oscfg.exe`/`gc_worker.exe` generates massive benign volume

---

*Built from production work. Every pattern validated in live environments.*
