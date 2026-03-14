// Ward Script - Cloud Storage Exfiltration Detection
// Detects data staging and exfiltration to personal cloud storage services
// (Google Drive, Dropbox, OneDrive Personal, WeTransfer, Mega).
// MITRE: T1567.002, T1048 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: Employees using approved cloud storage, marketing
//   teams sharing large files. Tune by user group and approved services.
// Required Repo: base_sensor (DNS + network) or web proxy logs
// Recommended Window: 24h
// ---

// === VARIANT A: DNS-Based Cloud Storage Detection ===
// Detect endpoints resolving personal cloud storage domains

#repo=base_sensor
| #event_simpleName=DnsRequest
| DomainName=/dropbox\.com|drive\.google\.com|mega\.nz|wetransfer\.com|mediafire\.com|sendspace\.com|anonfiles\.com|file\.io|gofile\.io|temp\.sh/i
| DomainName!=/dl\.dropboxusercontent\.com/i

// Exclude known approved services if applicable
// | DomainName!=/your-approved-domain\.com/i

| groupBy(
    [ComputerName, DomainName],
    function=[
      count(as=dns_lookups),
      min(@timestamp, as=first_lookup),
      max(@timestamp, as=last_lookup)
    ],
    span=24h
  )
| dns_lookups >= 5
| sort(dns_lookups, order=desc)


// === VARIANT B: Large Outbound Data Transfer ===
// Detect sustained large data transfers to external IPs

#repo=base_sensor
| #event_simpleName=NetworkConnectIP4
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2|3[01])\.|192\.168\.|127\.)/
| RemotePort=/443|80|8080/

| groupBy(
    [ComputerName, RemoteAddressIP4],
    function=[
      count(as=connection_count),
      min(@timestamp, as=first_conn),
      max(@timestamp, as=last_conn)
    ],
    span=1h
  )
| connection_count >= 100
| sort(connection_count, order=desc)

// High connection count to a single external IP in a short window
// may indicate bulk data upload. Cross-reference with DNS lookups
// and user activity.


// =====================================================================
// Ward Script - Email Forwarding Rule Exfiltration Detection
// Detects creation of email forwarding rules that could be used to
// exfiltrate data or maintain access to a compromised mailbox.
// MITRE: T1114.003, T1567 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: Users setting up legitimate forwarding to personal
//   email during job transitions, shared mailbox configurations.
// Required Repo: Microsoft 365 audit logs
// Recommended Window: 24h
// =====================================================================

#repo=<m365_audit_repo>
| @sourcetype=/microsoft|exchange|office365/i
| Operation=/New-InboxRule|Set-InboxRule|UpdateInboxRules|Set-Mailbox.*-ForwardingAddress|Set-Mailbox.*-ForwardingSmtpAddress/i

// Focus on rules that forward or redirect
| Parameters=/ForwardTo|RedirectTo|ForwardAsAttachmentTo|ForwardingAddress|ForwardingSmtpAddress/i

| select([
    @timestamp,
    UserId,
    Operation,
    Parameters,
    ClientIP
  ])
| sort(@timestamp, order=desc)

// === ANALYST NOTES ===
// HIGH RISK indicators:
//   - Forwarding to external/personal email domains (gmail, yahoo, hotmail)
//   - Rule created immediately after a risky sign-in
//   - Rule that forwards ALL mail (no conditions)
//   - Rule created with a name like "." or " " (hidden rule)
//   - Rule that also marks forwarded items as read and deletes them
//
// INVESTIGATION:
//   1. Check who created the rule — the user or a compromised session?
//   2. What's the forwarding destination? Internal or external?
//   3. When was the rule created relative to any sign-in anomalies?
//   4. Does the rule have conditions (specific subjects/senders)?
//   5. Check for other persistence mechanisms (MFA changes, app registrations)


// =====================================================================
// Ward Script - OAuth Application Consent Abuse Detection
// Detects potentially malicious OAuth app consent grants that could
// provide persistent access to a user's data.
// MITRE: T1550.001, T1098.003 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: Legitimate SaaS app onboarding, approved integrations.
// Required Repo: Identity provider / Entra ID audit logs
// Recommended Window: 7d
// =====================================================================

#repo=<identity_repo>
| @sourcetype=/entra|azuread|graph|azure_audit/i
| operationName=/Consent to application|Add app role assignment|Add OAuth2PermissionGrant/i

// Focus on high-privilege consent grants
| targetResource=/Mail\.Read|Mail\.ReadWrite|Files\.ReadWrite|User\.Read\.All|Directory\.Read\.All/i

| select([
    @timestamp,
    userPrincipalName,
    operationName,
    targetResource,
    ipAddress
  ])
| sort(@timestamp, order=desc)

// === ANALYST NOTES ===
// CONSENT PHISHING INDICATORS:
//   - User consented to an app they've never used before
//   - App requests Mail.ReadWrite + Files.ReadWrite (over-scoped)
//   - Consent occurred after a phishing email
//   - App name mimics Microsoft or known brands
//   - App publisher is unverified
//
// HIGH RISK PERMISSIONS:
//   - Mail.ReadWrite (read and send email as user)
//   - Files.ReadWrite.All (access all files)
//   - Directory.Read.All (read entire directory)
//   - User.Read.All (read all user profiles)
