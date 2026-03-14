// Ward Script - LOLBin Proxy Execution Detection
// Detects living-off-the-land binaries used to proxy malicious execution
// and bypass application whitelisting controls.
// MITRE: T1218.005, T1218.010, T1218.011, T1218.003 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: Legitimate use of these binaries by developers,
//   software installers, enterprise management tools.
// Required Repo: base_sensor
// Recommended Window: 24h
// ---

// === Mshta.exe with Remote Payload ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/mshta\.exe/i
| CommandLine=/http:|https:|javascript:|vbscript:|about:/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// Mshta executing remote HTA files or inline script = malicious


// === Regsvr32 Squiblydoo Attack ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/regsvr32\.exe/i
| CommandLine=/\/s.*\/n.*\/u.*\/i:|scrobj\.dll|http:|https:/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// Regsvr32 with /s /n /u /i:URL = Squiblydoo (COM scriptlet execution)


// === Rundll32 Suspicious Execution ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/rundll32\.exe/i
| CommandLine=/http:|https:|javascript:|\\\\\\\\|comsvcs|shell32.*ShellExec_RunDLL|pcwutl/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)


// === CMSTP UAC Bypass ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/cmstp\.exe/i
| CommandLine=/\/ni|\/s.*\.inf/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// CMSTP with /ni and an INF file = UAC bypass technique


// === Certutil Download Cradle ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/certutil\.exe/i
| CommandLine=/-urlcache|-verifyctl|-split.*http|decode.*\.exe/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// Certutil downloading or decoding files = download cradle or payload staging


// === BITSAdmin File Transfer ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/bitsadmin\.exe/i
| CommandLine=/\/transfer.*http|\/addfile/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)


// =====================================================================
// Ward Script - PowerShell Suspicious Execution Patterns
// Detects high-risk PowerShell usage patterns beyond simple encoding,
// including download cradles, AMSI bypass, reflection loading, and
// constrained language mode bypass.
// MITRE: T1059.001, T1562.001 | Severity: High-Critical | Author: Ethan Ward | v1.0
// False Positives: Some DevOps and admin scripts use these patterns
//   legitimately. Tune by parent process and script path.
// Required Repo: base_sensor
// Recommended Window: 24h
// =====================================================================

// === Download Cradles ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/powershell\.exe|pwsh\.exe/i
| CommandLine=/Invoke-WebRequest|Invoke-RestMethod|\.DownloadString\(|\.DownloadFile\(|Start-BitsTransfer|wget\s|curl\s.*http|IWR\s.*http|iex\s*\(|IEX\s*\(/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)


// === AMSI Bypass Attempts ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/powershell\.exe|pwsh\.exe/i
| CommandLine=/AmsiUtils|amsiInitFailed|SetValue.*amsi|Bypass|Reflection\.Assembly.*Load|AmsiScanBuffer/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// AMSI bypass = attacker trying to disable antimalware scanning
// This is almost always malicious in production environments


// === Reflection Loading (Fileless Malware) ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/powershell\.exe|pwsh\.exe/i
| CommandLine=/\[Reflection\.Assembly\]::Load|\[System\.Reflection\.Assembly\]::Load|Invoke-ReflectivePEInjection|Invoke-Shellcode/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// Reflection loading = loading .NET assemblies directly into memory
// without writing to disk. Classic fileless malware technique.


// === Execution Policy Bypass ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/powershell\.exe|pwsh\.exe/i
| CommandLine=/-[Ee]xecutionPolicy\s+(Bypass|Unrestricted)|Set-ExecutionPolicy\s+(Bypass|Unrestricted)/i
| ParentBaseFileName!=/services\.exe|svchost\.exe|CcmExec\.exe/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, GrandParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// Execution policy bypass from non-system parents = suspicious
// Many legit admin scripts do this, so check parent chain

// === ANALYST NOTES ===
// SEVERITY RANKING:
//   CRITICAL: AMSI bypass, reflection loading, encoded + download cradle
//   HIGH: Download cradles, LOLBin proxy execution
//   MEDIUM: Execution policy bypass (context-dependent)
//
// KEY PRINCIPLE:
//   No single LOLBin execution is definitive. The combination of
//   parent process chain + command line content + execution context
//   determines whether activity is malicious or legitimate.
//   Always reconstruct the full process tree before making a verdict.
