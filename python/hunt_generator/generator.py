"""
CQL Hunt Query Generator
Generates ready-to-run CrowdStrike NG-SIEM hunt queries from MITRE ATT&CK
technique IDs or threat intel indicators. Outputs queries with Ward Script
headers, analyst notes, and investigation pivots.

Author: Ethan Ward
Version: 1.0
"""

import json
import argparse
from datetime import datetime
from pathlib import Path


# Hunt query templates mapped to MITRE techniques
HUNT_TEMPLATES = {
    "T1059.001": {
        "name": "Encoded PowerShell Execution",
        "description": "Hunt for PowerShell processes with encoded commands, often used by malware and C2 frameworks",
        "tactic": "Execution",
        "query": r"""#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/powershell\.exe|pwsh\.exe/i
| CommandLine=/encodedcommand|-enc\s|-e\s|-ec\s/i

// Exclude known legitimate encoded commands (tune per environment)
// | CommandLine!=/known_legitimate_pattern/i

| select([
    @timestamp,
    ComputerName,
    UserName,
    CommandLine,
    ParentBaseFileName,
    GrandParentBaseFileName,
    SessionId,
    ParentProcessId,
    aid
  ])
| sort(@timestamp, order=desc)""",
        "notes": [
            "Decode base64 payload: echo '<encoded_string>' | base64 -d",
            "Check parent process — cmd.exe from explorer.exe = interactive",
            "LOLBin parents (mshta, wscript) = high confidence malicious",
            "SessionId=0 with encoded PS = likely malware running as service",
        ],
    },
    "T1059.003": {
        "name": "Suspicious cmd.exe Process Chains",
        "description": "Hunt for cmd.exe spawning processes commonly abused by attackers",
        "tactic": "Execution",
        "query": r"""#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ParentBaseFileName=/cmd\.exe/i
| ImageFileName=/certutil|bitsadmin|mshta|regsvr32|rundll32|wmic|cscript|wscript/i

| select([
    @timestamp,
    ComputerName,
    UserName,
    CommandLine,
    ImageFileName,
    ParentBaseFileName,
    GrandParentBaseFileName,
    SessionId,
    ParentProcessId,
    aid
  ])
| sort(@timestamp, order=desc)""",
        "notes": [
            "certutil with -urlcache = download cradle",
            "bitsadmin with /transfer = file download",
            "mshta with http:// = remote HTA execution",
            "Check grandparent — what spawned cmd.exe?",
        ],
    },
    "T1078": {
        "name": "Anomalous Valid Account Usage",
        "description": "Hunt for service accounts appearing on hosts outside their normal scope",
        "tactic": "Initial Access",
        "query": r"""#repo=base_sensor
| #event_simpleName=UserLogon
| UserName=/svc_|SA_|admin/i

// Build account-to-host map
| groupBy(
    [UserName],
    function=[
      count(as=logon_count),
      distinctCount(ComputerName, as=unique_hosts),
      collect([ComputerName, RemoteAddressIP4, LogonType], limit=30)
    ],
    span=24h
  )

// Flag accounts touching unusually many hosts
| unique_hosts >= 10
| sort(unique_hosts, order=desc)""",
        "notes": [
            "Service accounts should have predictable host patterns",
            "A service account on 50+ hosts when it normally touches 5 = investigate",
            "Check LogonType: 3=network, 10=RDP, 2=interactive",
            "RDP logon from a service account = almost certainly malicious",
        ],
    },
    "T1021.001": {
        "name": "Anomalous RDP Activity",
        "description": "Hunt for RDP connections from unexpected sources or to unexpected destinations",
        "tactic": "Lateral Movement",
        "query": r"""#repo=base_sensor
| #event_simpleName=UserLogon
| LogonType=10

| groupBy(
    [UserName, ComputerName],
    function=[
      count(as=rdp_sessions),
      collect([RemoteAddressIP4, @timestamp], limit=20),
      min(@timestamp, as=first_seen),
      max(@timestamp, as=last_seen)
    ],
    span=24h
  )

| sort(rdp_sessions, order=desc)""",
        "notes": [
            "LogonType=10 is RDP specifically",
            "Look for RDP to servers that don't normally receive RDP",
            "RDP from workstation-to-workstation is unusual in most environments",
            "Check source IP — is it internal or external?",
        ],
    },
    "T1053.005": {
        "name": "Scheduled Task Creation Anomalies",
        "description": "Hunt for scheduled tasks created by non-standard parent processes",
        "tactic": "Persistence",
        "query": r"""#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/schtasks\.exe/i
| CommandLine=/\/create/i

// Exclude standard system parents
| ParentBaseFileName!=/services\.exe|svchost\.exe|wmiprvse\.exe/i

| select([
    @timestamp,
    ComputerName,
    UserName,
    CommandLine,
    ParentBaseFileName,
    GrandParentBaseFileName,
    SessionId,
    ParentProcessId,
    aid
  ])
| sort(@timestamp, order=desc)""",
        "notes": [
            "schtasks from powershell/cmd in interactive session = check full tree",
            "Look at WHAT the task runs — encoded commands = malicious",
            "Task names mimicking Windows tasks = evasion attempt",
            "Check for task XML in C:\\Windows\\System32\\Tasks\\",
        ],
    },
    "T1087.002": {
        "name": "Domain Account Enumeration",
        "description": "Hunt for net.exe, dsquery, or PowerShell commands enumerating domain accounts and groups",
        "tactic": "Discovery",
        "query": r"""#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/net\s+(user|group|localgroup).*\/domain|dsquery\s+(user|group|computer)|Get-AD(User|Group|Computer)|Get-DomainUser|Get-DomainGroup/i

| select([
    @timestamp,
    ComputerName,
    UserName,
    CommandLine,
    ImageFileName,
    ParentBaseFileName,
    GrandParentBaseFileName,
    SessionId,
    ParentProcessId,
    aid
  ])
| sort(@timestamp, order=desc)""",
        "notes": [
            "Single 'net user /domain' = possibly normal admin work",
            "Rapid sequence of enumeration commands = recon phase of attack",
            "Get-Domain* = PowerView (offensive tool)",
            "Check if user normally performs AD administration",
        ],
    },
    "T1218": {
        "name": "LOLBin Proxy Execution",
        "description": "Hunt for living-off-the-land binaries used to proxy malicious execution",
        "tactic": "Defense Evasion",
        "query": r"""#repo=base_sensor
| #event_simpleName=ProcessRollup2
| ImageFileName=/mshta\.exe|regsvr32\.exe|rundll32\.exe|certutil\.exe|cmstp\.exe|installutil\.exe|msbuild\.exe/i

// Focus on suspicious command patterns
| CommandLine=/http:|https:|javascript:|\\\\\\\\|\/i:|scrobj|DotNetToJScript/i

| select([
    @timestamp,
    ComputerName,
    UserName,
    CommandLine,
    ImageFileName,
    ParentBaseFileName,
    GrandParentBaseFileName,
    SessionId,
    ParentProcessId,
    aid
  ])
| sort(@timestamp, order=desc)""",
        "notes": [
            "mshta + URL = remote HTA payload execution",
            "regsvr32 + /s /n /u /i:http = Squiblydoo attack",
            "certutil -urlcache = download cradle",
            "msbuild + inline task = code execution bypass",
            "Check if binary is running from expected path",
        ],
    },
    "T1558.003": {
        "name": "Kerberoasting Indicators",
        "description": "Hunt for SPN enumeration and abnormal TGS ticket requests indicating Kerberoasting",
        "tactic": "Credential Access",
        "query": r"""#repo=base_sensor
| #event_simpleName=ProcessRollup2
| CommandLine=/setspn|Get-SPNs|Invoke-Kerberoast|Rubeus.*kerberoast|servicePrincipalName/i

| select([
    @timestamp,
    ComputerName,
    UserName,
    CommandLine,
    ImageFileName,
    ParentBaseFileName,
    SessionId,
    aid
  ])
| sort(@timestamp, order=desc)""",
        "notes": [
            "setspn -T <domain> -Q */* = full SPN enumeration",
            "Invoke-Kerberoast or Rubeus = offensive tooling, high confidence",
            "Follow up with LDAP recon detection — Kerberoasting often follows recon",
            "Check for subsequent password cracking tool artifacts",
        ],
    },
}

# IOC-based hunt templates
IOC_TEMPLATES = {
    "ip": {
        "name": "Hunt by IP Address",
        "query": r"""#repo=base_sensor
| #event_simpleName=NetworkConnectIP4 OR #event_simpleName=DnsRequest
| RemoteAddressIP4="{ioc}"

| groupBy(
    [ComputerName, UserName],
    function=[
      count(as=connections),
      collect([RemotePort, @timestamp], limit=20)
    ]
  )
| sort(connections, order=desc)""",
    },
    "domain": {
        "name": "Hunt by Domain",
        "query": r"""#repo=base_sensor
| #event_simpleName=DnsRequest
| DomainName=/{ioc}/i

| groupBy(
    [ComputerName, UserName],
    function=[
      count(as=lookups),
      collect([DomainName, @timestamp], limit=20)
    ]
  )
| sort(lookups, order=desc)""",
    },
    "hash": {
        "name": "Hunt by File Hash",
        "query": r"""#repo=base_sensor
| #event_simpleName=ProcessRollup2
| SHA256HashData="{ioc}" OR MD5HashData="{ioc}"

| select([
    @timestamp,
    ComputerName,
    UserName,
    CommandLine,
    ImageFileName,
    ParentBaseFileName,
    aid
  ])
| sort(@timestamp, order=desc)""",
    },
    "filename": {
        "name": "Hunt by Filename",
        "query": r"""#repo=base_sensor
| #event_simpleName=ProcessRollup2 OR #event_simpleName=NewExecutableWritten
| FileName=/{ioc}/i OR TargetFileName=/{ioc}/i

| select([
    @timestamp,
    ComputerName,
    UserName,
    CommandLine,
    ImageFileName,
    TargetFileName,
    aid
  ])
| sort(@timestamp, order=desc)""",
    },
}


def generate_header(name: str, description: str, technique: str = "") -> str:
    """Generate a Ward Script header for a hunt query."""
    mitre_line = f"// MITRE: {technique} | " if technique else "// "
    return f"""// Ward Script - Hunt: {name}
// {description}
// {mitre_line}Type: Threat Hunt | Author: Ethan Ward | Generated: {datetime.now(tz=__import__("datetime").timezone.utc).strftime('%Y-%m-%d')}
// ---"""


def generate_technique_hunt(technique_id: str) -> str:
    """Generate a hunt query for a MITRE technique."""
    template = HUNT_TEMPLATES.get(technique_id)
    if not template:
        return f"// No hunt template available for {technique_id}\n// Available techniques: {', '.join(sorted(HUNT_TEMPLATES.keys()))}"

    header = generate_header(
        template["name"],
        template["description"],
        technique_id,
    )

    notes = "\n".join(f"//   - {note}" for note in template["notes"])

    return f"""{header}

{template['query']}

// === ANALYST NOTES ===
{notes}
"""


def generate_ioc_hunt(ioc_type: str, ioc_value: str) -> str:
    """Generate a hunt query for an IOC."""
    template = IOC_TEMPLATES.get(ioc_type)
    if not template:
        return f"// Unknown IOC type: {ioc_type}\n// Supported types: {', '.join(IOC_TEMPLATES.keys())}"

    header = generate_header(
        f"{template['name']}: {ioc_value}",
        f"Hunting for {ioc_type} indicator: {ioc_value}",
    )

    query = template["query"].replace("{ioc}", ioc_value)

    return f"""{header}

{query}
"""


def main():
    parser = argparse.ArgumentParser(
        description="CQL Hunt Query Generator"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Technique-based hunt
    tech_parser = subparsers.add_parser("technique", help="Generate hunt from MITRE technique ID")
    tech_parser.add_argument("--id", type=str, required=True, help="MITRE technique ID (e.g., T1059.001)")
    tech_parser.add_argument("--output", type=str, help="Output file path")

    # IOC-based hunt
    ioc_parser = subparsers.add_parser("ioc", help="Generate hunt from IOC")
    ioc_parser.add_argument("--type", type=str, required=True, choices=["ip", "domain", "hash", "filename"])
    ioc_parser.add_argument("--value", type=str, required=True, help="IOC value")
    ioc_parser.add_argument("--output", type=str, help="Output file path")

    # List available templates
    subparsers.add_parser("list", help="List available hunt templates")

    args = parser.parse_args()

    if args.command == "technique":
        result = generate_technique_hunt(args.id)
        print(result)
        if args.output:
            Path(args.output).write_text(result)
            print(f"\n[+] Saved to {args.output}")

    elif args.command == "ioc":
        result = generate_ioc_hunt(args.type, args.value)
        print(result)
        if args.output:
            Path(args.output).write_text(result)
            print(f"\n[+] Saved to {args.output}")

    elif args.command == "list":
        print("\n[*] Available MITRE Technique Hunt Templates:\n")
        for tech_id, template in sorted(HUNT_TEMPLATES.items()):
            print(f"  {tech_id:<14} {template['name']:<45} [{template['tactic']}]")
        print(f"\n[*] Available IOC Types: {', '.join(IOC_TEMPLATES.keys())}\n")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
