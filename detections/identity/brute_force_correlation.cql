// Ward Script - Distributed Brute Force Correlation
// Detects password spray and distributed brute force attacks by correlating
// failed authentication attempts across multiple accounts from a single source IP,
// or against a single account from multiple source IPs. Uses dual-pivot logic
// to catch both spray (many users, one IP) and distributed (one user, many IPs) patterns.
// MITRE: T1110.003, T1110.004 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: Vulnerability scanners, SSO misconfigurations, expired service
//   account credentials hitting multiple endpoints. Tune IP and account exclusions.
// Required Repo: Identity provider logs (Okta, Entra ID, or base_sensor UserLogon)
// Recommended Window: 1h
// ---

// === VARIANT A: Password Spray Detection (Many Users from Single IP) ===

#repo=<identity_repo>
| eventType=/authentication|sign-in|UserLogon/i
| outcome=/FAILURE|failed/i
| sourceIp=*
| userName=*

// Exclude known infrastructure
// | sourceIp!=/10\.0\.0\.1|192\.168\.1\.1/
// | userName!=/svc_|healthcheck/i

| groupBy(
    [sourceIp],
    function=[
      count(as=total_failures),
      distinctCount(userName, as=unique_users_targeted),
      collect([userName], limit=25)
    ],
    span=59m
  )

// Spray pattern: many unique users from one IP
| unique_users_targeted >= 10
| total_failures >= 15

| spray_confidence := case {
    unique_users_targeted >= 50 => "CRITICAL";
    unique_users_targeted >= 25 => "HIGH";
    unique_users_targeted >= 10 => "MEDIUM";
    * => "LOW";
  }

| sort(unique_users_targeted, order=desc)


// === VARIANT B: Distributed Brute Force (Single User from Many IPs) ===

#repo=<identity_repo>
| eventType=/authentication|sign-in|UserLogon/i
| outcome=/FAILURE|failed/i
| sourceIp=*
| userName=*

| groupBy(
    [userName],
    function=[
      count(as=total_failures),
      distinctCount(sourceIp, as=unique_source_ips),
      collect([sourceIp], limit=25)
    ],
    span=59m
  )

// Distributed pattern: many IPs targeting one user
| unique_source_ips >= 5
| total_failures >= 20

| distributed_confidence := case {
    unique_source_ips >= 20 => "CRITICAL";
    unique_source_ips >= 10 => "HIGH";
    unique_source_ips >= 5 => "MEDIUM";
    * => "LOW";
  }

| sort(unique_source_ips, order=desc)


// === VARIANT C: Spray Followed by Success (Highest Fidelity) ===
// Detects a spray pattern followed by a successful login from the same IP

#repo=<identity_repo>
| eventType=/authentication|sign-in|UserLogon/i
| sourceIp=*
| userName=*

| auth_result := case {
    outcome=/SUCCESS|success/i => "success";
    outcome=/FAILURE|failed/i => "failure";
    * => "unknown";
  }

| groupBy(
    [sourceIp],
    function=[
      count(as=total_attempts),
      sum(if(auth_result="failure", then=1, else=0), as=failures),
      sum(if(auth_result="success", then=1, else=0), as=successes),
      distinctCount(userName, as=unique_users),
      collect([userName, auth_result], limit=30)
    ],
    span=59m
  )

// Spray pattern with at least one success
| failures >= 15
| unique_users >= 10
| successes >= 1

// This is the highest fidelity variant — spray + success = likely compromise
| sort(successes, order=desc)

// === ANALYST NOTES ===
// TRUE POSITIVE indicators:
//   - Spray from a cloud hosting provider IP (AWS, Azure, DigitalOcean)
//   - Sequential usernames targeted (alphabetical enumeration)
//   - Success follows spray from same IP = account likely compromised
//   - Source IP not associated with corporate VPN or office egress
//
// INVESTIGATION PIVOT:
//   1. Check if the successful account has MFA — if not, assume compromised
//   2. Review what the successful session did (mail access, file downloads, MFA changes)
//   3. Geo-locate the source IP — does it match user's normal location?
//   4. Check for token replay or session hijacking indicators
//   5. Cross-reference with impossible travel detection
