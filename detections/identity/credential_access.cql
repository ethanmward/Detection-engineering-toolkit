// Ward Script - Credential Dumping Tool Detection
// Detects common credential dumping tools and techniques including
// Mimikatz, LSASS memory access, SAM database extraction, and
// DCSync attacks.
// MITRE: T1003.001, T1003.002, T1003.003, T1003.006 | Severity: Critical | Author: Ethan Ward | v1.0
// False Positives: Endpoint protection tools accessing LSASS,
//   legitimate backup solutions accessing SAM, security testing.
// Required Repo: base_sensor
// Recommended Window: 24h
// ---

// === VARIANT A: Mimikatz and Known Tool Signatures ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/mimikatz|sekurlsa::logonpasswords|lsadump::sam|lsadump::dcsync|kerberos::golden|crypto::certificates|token::elevate|privilege::debug/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName,
    SessionId, ParentProcessId, aid
  ])
| sort(@timestamp, order=desc)

// NOTE: Any hit on this is near-certain malicious activity.
// Mimikatz command strings in CommandLine = immediate escalation.


// === VARIANT B: LSASS Memory Access via Procdump or Comsvcs ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| (CommandLine=/procdump.*lsass/i)
  OR (CommandLine=/comsvcs\.dll.*MiniDump/i)
  OR (CommandLine=/rundll32.*comsvcs.*full/i)
  OR (CommandLine=/Out-Minidump.*lsass/i)
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// NOTE: These are LOLBin-based LSASS dumping techniques.
// comsvcs.dll MiniDump is particularly common because it
// uses a built-in Windows DLL to avoid dropping tools.


// === VARIANT C: SAM/SYSTEM/SECURITY Hive Extraction ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/reg\s+save\s+HKLM\\(SAM|SYSTEM|SECURITY)/i
  OR CommandLine=/esentutl.*\/y.*ntds/i
  OR CommandLine=/ntdsutil.*activate.*ifm/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// NOTE: Extracting SAM/SYSTEM hives allows offline password cracking.
// ntdsutil/esentutl targeting ntds.dit = Active Directory database theft.


// === VARIANT D: DCSync Detection ===
// DCSync uses Directory Replication Service to extract credentials
// Look for non-DC machines making replication requests

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/lsadump::dcsync|DRS.*GetNCChanges|1131f6aa-9c07-11d1-f79f|1131f6ad-9c07-11d1-f79f/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, aid
  ])
| sort(@timestamp, order=desc)

// The GUIDs are the replication rights:
// 1131f6aa = DS-Replication-Get-Changes
// 1131f6ad = DS-Replication-Get-Changes-All


// =====================================================================
// Ward Script - Kerberoasting Detection
// Detects SPN enumeration and Kerberoasting tool execution patterns.
// MITRE: T1558.003 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: Legitimate SPN queries by admins, service account
//   management scripts.
// Required Repo: base_sensor
// Recommended Window: 24h
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/Invoke-Kerberoast|Rubeus.*kerberoast|GetUserSPNs|setspn\s+-T\s+.*-Q\s+\*|servicePrincipalName=\*/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName,
    SessionId, aid
  ])
| sort(@timestamp, order=desc)

// === ANALYST NOTES ===
// Kerberoasting attack chain:
//   1. Enumerate SPNs (setspn or LDAP query)
//   2. Request TGS tickets for service accounts
//   3. Extract ticket hashes
//   4. Crack offline (hashcat/john)
//
// INVESTIGATION:
//   - Check LDAP recon detection for preceding enumeration
//   - Look for subsequent authentication anomalies
//   - Identify which service account SPNs were targeted
//   - Check if targeted service accounts have weak passwords


// =====================================================================
// Ward Script - Suspicious Authentication Token Manipulation
// Detects token impersonation and privilege escalation via token theft.
// MITRE: T1134.001, T1134.003 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: Some admin tools legitimately manipulate tokens.
// Required Repo: base_sensor
// Recommended Window: 24h
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/Invoke-TokenManipulation|incognito.*list_tokens|incognito.*impersonate|token::elevate|whoami\s+\/priv.*SeDebugPrivilege|Invoke-RevertToSelf/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)
