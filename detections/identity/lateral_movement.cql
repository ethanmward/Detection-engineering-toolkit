// Ward Script - PsExec and SMB Lateral Movement Detection
// Detects lateral movement via PsExec, SMB admin share access,
// and remote service creation patterns.
// MITRE: T1021.002, T1570, T1569.002 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: IT admin tools using PsExec for legitimate remote
//   management, SCCM deployments, backup solutions.
// Required Repo: base_sensor
// Recommended Window: 24h
// ---

// === VARIANT A: PsExec Execution ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/PSEXESVC\.exe|psexec\.exe/i
  OR (ParentBaseFileName=/services\.exe/i AND FileName=/psexesvc/i)
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, GrandParentBaseFileName,
    SessionId, aid
  ])
| sort(@timestamp, order=desc)

// NOTE: PSEXESVC.exe is the service component that PsExec installs
// on the remote machine. Its presence means someone used PsExec
// to execute commands on this host remotely.


// === VARIANT B: SMB Admin Share Access ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/\\\\[A-Za-z0-9].*\\(ADMIN\$|C\$|IPC\$)/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)


// === VARIANT C: Remote Service Creation ===
// Attackers create services on remote hosts for code execution

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/sc\.exe/i
| CommandLine=/\\\\.*create|\\\\.*start/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)


// =====================================================================
// Ward Script - WMI Remote Execution Detection
// Detects WMI-based lateral movement and remote code execution.
// MITRE: T1047 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: SCCM client operations, legitimate WMI-based
//   monitoring tools, admin scripts.
// Required Repo: base_sensor
// Recommended Window: 24h
// =====================================================================

// === Remote WMI Process Creation ===

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/wmic.*\/node:.*process\s+call\s+create/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)


// === WmiPrvSE Spawning Suspicious Children ===
// When WMI executes a command remotely, WmiPrvSE.exe spawns the process

#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ParentBaseFileName=/WmiPrvSE\.exe/i
| ImageFileName!=/WmiPrvSE\.exe|svchost\.exe|mofcomp\.exe|WmiApSrv\.exe/i
| ImageFileName=/cmd\.exe|powershell\.exe|pwsh\.exe|mshta\.exe|cscript\.exe|wscript\.exe|certutil\.exe|rundll32\.exe|regsvr32\.exe/i
| select([
    @timestamp, ComputerName, UserName, CommandLine,
    ImageFileName, ParentBaseFileName, SessionId, aid
  ])
| sort(@timestamp, order=desc)

// NOTE: WmiPrvSE.exe spawning cmd/powershell/LOLBins is a strong
// indicator of remote WMI execution. Check if the command was
// initiated from another host.


// =====================================================================
// Ward Script - RDP Lateral Movement Anomaly Detection
// Detects anomalous RDP usage patterns including workstation-to-workstation
// RDP, RDP from service accounts, and RDP session pivoting.
// MITRE: T1021.001 | Severity: Medium-High | Author: Ethan Ward | v1.0
// False Positives: IT helpdesk remote support, admin jump boxes.
// Required Repo: base_sensor
// Recommended Window: 24h
// =====================================================================

// === RDP Logon Events ===

#repo=base_sensor
| #event_simpleName=UserLogon
| LogonType=10
| UserName=*
| ComputerName=*

// Exclude known jump boxes and admin workstations
// | ComputerName!=/JUMPBOX|ADMIN-WS/i

| groupBy(
    [UserName, ComputerName, RemoteAddressIP4],
    function=[
      count(as=rdp_sessions),
      min(@timestamp, as=first_rdp),
      max(@timestamp, as=last_rdp)
    ],
    span=24h
  )
| sort(rdp_sessions, order=desc)


// === Service Account RDP Detection ===
// Service accounts should never use RDP

#repo=base_sensor
| #event_simpleName=UserLogon
| LogonType=10
| UserName=/^svc[_-]|^SA[_-]/i
| select([
    @timestamp, ComputerName, UserName, RemoteAddressIP4, aid
  ])
| sort(@timestamp, order=desc)

// NOTE: Service accounts using RDP (LogonType=10) is almost never
// legitimate. This indicates either compromised credentials or
// an insider threat using a service account to mask activity.


// === RDP Session Pivoting ===
// Detects a user RDP'ing to host A, then from host A to host B

#repo=base_sensor
| #event_simpleName=UserLogon
| LogonType=10
| UserName=*
| groupBy(
    [UserName],
    function=[
      count(as=total_rdp),
      distinctCount(ComputerName, as=unique_destinations),
      collect([ComputerName, RemoteAddressIP4], limit=20)
    ],
    span=4h
  )
| unique_destinations >= 3
| sort(unique_destinations, order=desc)

// Users RDP'ing to 3+ hosts within 4 hours may be pivoting
// through the network. Check if this matches known admin behavior.

// === ANALYST NOTES ===
// LATERAL MOVEMENT INDICATORS:
//   - Workstation-to-workstation RDP (not server)
//   - Service account using RDP
//   - User RDP'ing to 3+ hosts in rapid succession
//   - RDP from a host that was recently compromised
//   - RDP combined with other TTPs (credential dump → RDP)
//
// INVESTIGATION:
//   1. What did the user do after RDP session started?
//   2. Were any files copied or tools dropped?
//   3. Is this user normally an RDP user?
//   4. Check process tree on destination host during RDP session
