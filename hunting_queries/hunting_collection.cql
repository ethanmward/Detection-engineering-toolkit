// =====================================================================
// Ward Script - Hunting Query Collection
// Ready-to-run CQL queries for proactive threat hunting in CrowdStrike
// NG-SIEM. Organized by hunt hypothesis.
// Author: Ethan Ward
// =====================================================================


// =====================================================================
// HUNT 01: Encoded PowerShell Execution
// Hypothesis: Attackers use base64-encoded PowerShell to evade detection
// MITRE: T1059.001
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/powershell\.exe|pwsh\.exe/i
| CommandLine=/encodedcommand|-enc\s|-e\s|-ec\s|-en\s/i
| ParentBaseFileName!=/services\.exe|svchost\.exe/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)


// =====================================================================
// HUNT 02: LOLBin Download Cradles
// Hypothesis: Attackers use trusted binaries to download malicious payloads
// MITRE: T1105, T1218
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/certutil.*-urlcache|bitsadmin.*\/transfer|Invoke-WebRequest|wget\s|curl\s.*http|Start-BitsTransfer|\.DownloadString\(|\.DownloadFile\(/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName, aid
  ])
| sort(@timestamp, order=desc)


// =====================================================================
// HUNT 03: Suspicious Account Creation
// Hypothesis: Attackers create local accounts for persistence
// MITRE: T1136.001
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/net\s+(user|localgroup).*\/add/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)


// =====================================================================
// HUNT 04: Anomalous Service Account Behavior
// Hypothesis: Compromised service accounts operate outside normal scope
// MITRE: T1078
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| UserName=/^svc[_-]|^SA[_-]/i
| GrandParentBaseFileName=/explorer\.exe/i
| SessionId!="0"
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName,
    SessionId, aid
  ])
| sort(@timestamp, order=desc)

// NOTE: Service accounts with interactive sessions (explorer.exe grandparent,
// SessionId > 0) are almost never legitimate. This indicates someone logged
// in interactively with a service account — investigate immediately.


// =====================================================================
// HUNT 05: Credential Dumping Tool Indicators
// Hypothesis: Attackers use known tools to dump credentials from memory
// MITRE: T1003
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs\.dll.*MiniDump|nanodump|pypykatz|crackmapexec.*--lsa/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)


// =====================================================================
// HUNT 06: Lateral Movement via PsExec / SMB
// Hypothesis: Attackers use PsExec or SMB for lateral movement
// MITRE: T1021.002, T1570
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/psexe(c|svc)\.exe|PSEXESVC\.exe/i
  OR CommandLine=/\\\\.*\\(ADMIN|C|IPC)\$/i
  OR (ParentBaseFileName=/services\.exe/i AND FileName=/psexesvc/i)
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName, aid
  ])
| sort(@timestamp, order=desc)


// =====================================================================
// HUNT 07: WMI Remote Execution
// Hypothesis: Attackers use WMI for fileless lateral movement
// MITRE: T1047
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| (CommandLine=/wmic.*\/node:.*process\s+call\s+create/i)
  OR (ParentBaseFileName=/WmiPrvSE\.exe/i AND ImageFileName!=/WmiPrvSE|svchost|mofcomp/i)
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName, aid
  ])
| sort(@timestamp, order=desc)


// =====================================================================
// HUNT 08: Registry Persistence Mechanisms
// Hypothesis: Attackers modify Run/RunOnce keys for persistence
// MITRE: T1547.001
// =====================================================================

#repo=base_sensor
| #event_simpleName=AsepValueUpdate OR #event_simpleName=RegKeyValueSet
| RegObjectName=/\\CurrentVersion\\Run|\\CurrentVersion\\RunOnce|\\CurrentVersion\\Explorer\\Shell Folders/i
| RegObjectName!=/\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth/i
| select([
    @timestamp, ComputerName, UserName,
    RegObjectName, RegValueName, aid
  ])
| sort(@timestamp, order=desc)


// =====================================================================
// HUNT 09: DNS Tunneling Indicators
// Hypothesis: Attackers exfiltrate data or communicate via DNS
// MITRE: T1071.004
// =====================================================================

#repo=base_sensor
| #event_simpleName=DnsRequest
| DomainName=*

// Hunt for unusually long subdomains (potential DNS tunneling)
// Normal: www.google.com (short subdomain)
// Tunneling: aGVsbG8gd29ybGQ.evil.com (base64-encoded data)
| groupBy(
    [ComputerName, DomainName],
    function=[count(as=query_count)]
  )
| query_count >= 100
| sort(query_count, order=desc, limit=50)

// Follow up: check domain length and entropy for flagged domains


// =====================================================================
// HUNT 10: Suspicious Parent-Child Process Relationships
// Hypothesis: Certain process parent-child combos indicate exploitation
// MITRE: T1203
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| (
    (ParentBaseFileName=/winword\.exe|excel\.exe|powerpnt\.exe/i
     AND ImageFileName=/cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe/i)
    OR
    (ParentBaseFileName=/outlook\.exe/i
     AND ImageFileName=/powershell\.exe|cmd\.exe/i)
    OR
    (ParentBaseFileName=/svchost\.exe/i
     AND ImageFileName=/cmd\.exe|powershell\.exe/i
     AND UserName!=/SYSTEM|\$$/i)
  )
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName,
    SessionId, ParentProcessId, aid
  ])
| sort(@timestamp, order=desc)

// NOTE: Office apps spawning shell processes is a classic exploitation indicator.
// Word/Excel → cmd/powershell = macro execution or exploit
// Outlook → powershell = email-based attack chain
