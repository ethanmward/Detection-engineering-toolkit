// Ward Script - UAC Bypass via Registry Modification
// Detects attempts to disable User Account Control by modifying the EnableLUA
// registry value. This is a common defense evasion technique used by malware
// families including CoronaVirus ransomware, Remcos RAT, and GuLoader.
// MITRE: T1548.002, T1112 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: Azure Guest Configuration compliance scans (oscfg.exe),
//   SCCM/Intune compliance checks, GPO enforcement scripts.
//   Key: check if the process READS vs WRITES the value.
// Required Repo: base_sensor
// Recommended Window: 24h
// ---
// CRITICAL FALSE POSITIVE NOTE:
//   Azure Guest Configuration (oscfg.exe → gc_worker.exe) runs compliance checks
//   that REFERENCE EnableLUA in the CommandLine but only READ the value
//   (resource status show). This generates thousands of events daily.
//   The parent process chain: gc_worker.exe → oscfg.exe → reg.exe
//   Path: C:\ProgramData\GuestConfig\Configuration\AzureWindowsBaseline
//   These are 100% benign and MUST be excluded.
// ---

// === DETECTION: UAC Bypass via EnableLUA ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/EnableLUA/i

// === EXCLUSIONS: Known False Positive Sources ===
// Azure Guest Configuration
| ParentBaseFileName!=/oscfg\.exe|gc_worker\.exe/i
| CommandLine!=/resource status show/i
| FilePath!=/GuestConfig/i

// SCCM/Intune compliance
| ParentBaseFileName!=/CcmExec\.exe|IntuneManagementExtension\.exe/i

// === Focus on WRITE operations ===
// Only flag commands that MODIFY the value (ADD, /d 0)
| CommandLine=/ADD.*EnableLUA.*\/d\s*0|EnableLUA.*\/d\s*0/i

// === Enrich with Context ===
| execution_context := case {
    GrandParentBaseFileName=/explorer\.exe/i => "interactive_session";
    GrandParentBaseFileName=/services\.exe/i => "service_context";
    SessionId="0" => "system_session";
    * => "unknown_context";
  }

| account_type := case {
    UserName=/\$$/ => "machine_account";
    UserSid=/S-1-5-18/ => "SYSTEM";
    * => "user_account";
  }

| select([
    @timestamp,
    ComputerName,
    UserName,
    account_type,
    CommandLine,
    ImageFileName,
    ParentBaseFileName,
    GrandParentBaseFileName,
    execution_context,
    SessionId,
    ParentProcessId,
    aid
  ])

| sort(@timestamp, order=desc)

// === FOLLOW-UP: Check for Corroborating TTPs ===
// A single EnableLUA modification is suspicious but not conclusive.
// Check for additional indicators that suggest ransomware or RAT:

// 1. Wallpaper change (ransomware indicator):
// #repo=base_sensor
// | #event_simpleName=RegKeyValueSet
// | RegObjectName=/Desktop\\Wallpaper/i
// | ComputerName=/AFFECTED_HOST/i

// 2. Task Manager disable (ransomware indicator):
// #repo=base_sensor
// | #event_simpleName=ProcessRollup2
// | CommandLine=/DisableTaskMgr/i
// | ComputerName=/AFFECTED_HOST/i

// 3. Scheduled task creation from suspicious parent:
// #repo=base_sensor
// | #event_simpleName=ProcessRollup2
// | CommandLine=/schtasks.*\/create/i
// | ParentBaseFileName!=/services\.exe|svchost\.exe/i

// 4. Cursor modification (CoronaVirus ransomware specific):
// #repo=base_sensor
// | #event_simpleName=RegKeyValueSet
// | RegObjectName=/Control Panel\\Cursors/i

// === VERDICT DECISION ===
// Single TTP (EnableLUA only) + Azure/SCCM parent = FALSE POSITIVE
// Single TTP + unknown parent + interactive session = INVESTIGATE
// Multiple TTPs (EnableLUA + wallpaper + taskmanager) = LIKELY MALICIOUS
// EnableLUA + encoded PowerShell in process tree = ESCALATE IMMEDIATELY


// =====================================================================
// Ward Script - Browser Extension Hijack Artifacts
// Detects persistence via malicious browser extension installation by
// identifying extension-related file writes and registry modifications
// outside of normal browser update patterns.
// MITRE: T1176 | Severity: Medium | Author: Ethan Ward | v1.0
// False Positives: Legitimate extension installs via enterprise policy,
//   browser updates, managed extensions via GPO.
// Required Repo: base_sensor
// Recommended Window: 24h
// =====================================================================

#repo=base_sensor
| #event_simpleName=NewExecutableWritten OR #event_simpleName=GenericFileWritten
| TargetFileName=/\\Extensions\\/i
| TargetFileName=/\.js$|\.json$|manifest\.json/i

// Exclude known browser update paths
| TargetFileName!=/\\Google\\Chrome\\Application\\|\\Microsoft\\Edge\\Application\\/i

// Flag extensions written by non-browser processes
| ContextBaseFileName!=/chrome\.exe|msedge\.exe|firefox\.exe|brave\.exe/i

| select([
    @timestamp,
    ComputerName,
    UserName,
    ContextBaseFileName,
    TargetFileName,
    aid
  ])

| sort(@timestamp, order=desc)


// =====================================================================
// Ward Script - Scheduled Task Creation from Suspicious Parent
// Detects schtasks.exe /create invoked by processes that don't normally
// create scheduled tasks. Common persistence mechanism for malware.
// MITRE: T1053.005 | Severity: Medium-High | Author: Ethan Ward | v1.0
// False Positives: Software installers, SCCM deployments, IT automation.
// Required Repo: base_sensor
// Recommended Window: 24h
// =====================================================================

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/schtasks\.exe/i
| CommandLine=/\/create/i

// === Suspicious Parent Processes ===
// Flag when schtasks is spawned by processes that shouldn't create tasks
| ParentBaseFileName=/powershell\.exe|pwsh\.exe|cmd\.exe|wscript\.exe|cscript\.exe|mshta\.exe|regsvr32\.exe|rundll32\.exe/i

// Exclude known legitimate automation
// | CommandLine!=/\\Microsoft\\Windows\\UpdateOrchestrator/i
// | CommandLine!=/\\SCCM\\|\\CCM\\/i

| suspicion := case {
    ParentBaseFileName=/mshta\.exe|regsvr32\.exe|rundll32\.exe/i => "HIGH";
    ParentBaseFileName=/wscript\.exe|cscript\.exe/i => "HIGH";
    ParentBaseFileName=/powershell\.exe|pwsh\.exe/i AND CommandLine=/encodedcommand|-enc|-e /i => "CRITICAL";
    ParentBaseFileName=/cmd\.exe/i => "MEDIUM";
    * => "LOW";
  }

| select([
    @timestamp,
    ComputerName,
    UserName,
    CommandLine,
    ParentBaseFileName,
    GrandParentBaseFileName,
    suspicion,
    SessionId,
    ParentProcessId,
    aid
  ])

| sort(@timestamp, order=desc)

// === ANALYST NOTES ===
// CRITICAL: schtasks /create from encoded PowerShell = near certain malicious
// HIGH: schtasks from LOLBins (mshta, regsvr32, rundll32, wscript)
// MEDIUM: schtasks from cmd.exe — check grandparent and full process tree
//
// INVESTIGATION:
//   1. Reconstruct full process tree from ParentProcessId
//   2. Check what the scheduled task is configured to run
//   3. Look for the task XML in registry or file system
//   4. Check if the task persists across reboots
//   5. Correlate with network activity from the same host/user
