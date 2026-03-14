// Ward Script - GuLoader Delivery Chain Detection
// Detects GuLoader initial delivery patterns including VBScript/PowerShell
// download cradles, process hollowing indicators, and characteristic
// shellcode injection into legitimate Windows processes.
// MITRE: T1059.005, T1055.012, T1105 | Severity: Critical | Author: Ethan Ward | v1.0
// False Positives: Rare. GuLoader patterns are highly specific.
// Required Repo: base_sensor
// Recommended Window: 24h
// ---

// === VARIANT A: VBScript/PowerShell Download Cradle ===
// GuLoader commonly arrives via VBS or PS1 attached to phishing emails

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| (ParentBaseFileName=/wscript\.exe|cscript\.exe/i
   AND ImageFileName=/powershell\.exe|cmd\.exe|curl\.exe|certutil\.exe/i)
| CommandLine=/http|https|ftp|\.exe|\.dll|\.bin|Invoke-|DownloadString|DownloadFile|urlcache|Start-BitsTransfer/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName,
    SessionId, ParentProcessId, aid
  ])
| sort(@timestamp, order=desc)


// === VARIANT B: Process Hollowing / Injection Indicators ===
// GuLoader injects into legitimate processes like RegAsm.exe, MSBuild.exe,
// InstallUtil.exe, or RegSvcs.exe

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/RegAsm\.exe|MSBuild\.exe|InstallUtil\.exe|RegSvcs\.exe|AddInProcess\.exe/i
| ParentBaseFileName!=/services\.exe|svchost\.exe|msiexec\.exe|devenv\.exe|w3wp\.exe/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName,
    SessionId, ParentProcessId, aid
  ])
| sort(@timestamp, order=desc)

// NOTE: These .NET binaries being spawned by anything other than
// development tools or system services is highly suspicious.
// GuLoader uses them as injection targets for shellcode execution.


// =====================================================================
// Ward Script - Remcos RAT Indicator Detection
// Detects Remcos RAT post-exploitation indicators including registry
// persistence keys, known mutex patterns, and characteristic process
// behavior.
// MITRE: T1219, T1547.001, T1112 | Severity: Critical | Author: Ethan Ward | v1.0
// False Positives: None expected for Remcos-specific patterns.
// Required Repo: base_sensor
// Recommended Window: 24h
// =====================================================================

// === Registry Persistence (Remcos writes to Run keys) ===

#repo=base_sensor
| #event_simpleName=AsepValueUpdate OR #event_simpleName=RegKeyValueSet
| RegObjectName=/\\CurrentVersion\\Run/i
| RegValueName=/remcos|syscfg|winlogon_update|desktop_app/i
| select([
    @timestamp, ComputerName, UserName,
    RegObjectName, RegValueName, aid
  ])
| sort(@timestamp, order=desc)


// === Process Behavior (Remcos spawns from unusual locations) ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/\\AppData\\(Local|Roaming)\\.*\.exe/i
| CommandLine!=/chrome|firefox|discord|spotify|teams|slack|zoom|onedrive|dropbox/i
| ParentBaseFileName=/explorer\.exe/i
| SessionId!="0"
| groupBy([ComputerName, UserName, ImageFileName], function=count())
| sort(_count, order=desc)

// NOTE: Executables running from AppData spawned by explorer.exe
// that aren't known applications warrant investigation.
// Remcos commonly drops itself in AppData\Roaming or AppData\Local.


// === Network Callback Detection ===
// Remcos uses configurable C2 on non-standard ports

#repo=base_sensor
| #event_simpleName=NetworkConnectIP4
| RemotePort!=/^(80|443|8080|8443|53)$/
| LocalAddressIP4=/^(10\.|172\.(1[6-9]|2|3[01])\.|192\.168\.)/
| groupBy(
    [ComputerName, RemoteAddressIP4, RemotePort],
    function=[count(as=connections), min(@timestamp), max(@timestamp)]
  )
| connections >= 10
| sort(connections, order=desc)

// Sustained outbound connections to non-standard ports from internal
// hosts may indicate C2 beaconing. Cross-reference RemoteAddressIP4
// with threat intel feeds.
