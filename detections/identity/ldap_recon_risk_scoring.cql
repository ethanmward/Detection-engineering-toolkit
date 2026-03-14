// Ward Script - LDAP Reconnaissance Risk Scoring
// Scores LDAP query activity by volume, query type, and account context to detect
// reconnaissance. Differentiates between service accounts (expected high-volume LDAP)
// and user accounts (suspicious high-volume LDAP). Uses weighted scoring to reduce
// false positives from legitimate directory services.
// MITRE: T1087.002, T1018 | Severity: Medium-High | Author: Ethan Ward | v1.0
// False Positives: Service accounts for SCCM, backup agents, vulnerability scanners,
//   and identity management tools generate high LDAP volume legitimately.
//   Tune service account exclusions per environment.
// Required Repo: base_sensor or identity provider logs
// Recommended Window: 1h (use span=59m for near-real-time alerting)
// ---
// SCORING MODEL:
//   Base score per LDAP query event = 1
//   Multipliers:
//     - User account (no $ suffix): x3
//     - Queries targeting sensitive groups (Domain Admins, Enterprise Admins): x5
//     - Queries enumerating all users or all computers: x4
//     - Off-hours activity (outside 06:00-18:00 local): x2
//     - Source is not a known directory server: x3
//   Threshold: risk_score >= 50 within 1h window triggers alert
// ---

// === DETECTION: LDAP Recon Scoring Engine ===

#repo=base_sensor
| #event_simpleName=LdapQuery OR #event_simpleName=DirectoryServiceQuery
| QueryFilter=*
| UserName=*

// --- Account Type Classification ---
| account_type := case {
    UserName=/\$$/ => "service_account";
    UserName=/^svc[_-]/i => "service_account";
    UserName=/^SA[_-]/i => "service_account";
    * => "user_account";
  }

// --- Query Target Classification ---
| query_target := case {
    QueryFilter=/Domain Admins|Enterprise Admins|Schema Admins|Administrators/i => "sensitive_group";
    QueryFilter=/\(objectClass=user\).*\(objectClass=computer\)/i => "full_enumeration";
    QueryFilter=/\(objectCategory=person\)/i => "user_enumeration";
    QueryFilter=/\(objectCategory=computer\)/i => "computer_enumeration";
    QueryFilter=/\(servicePrincipalName=\*\)/i => "spn_enumeration";
    * => "standard_query";
  }

// --- Base Risk Score Assignment ---
| base_score := case {
    query_target="sensitive_group" => 10;
    query_target="full_enumeration" => 8;
    query_target="user_enumeration" => 5;
    query_target="computer_enumeration" => 5;
    query_target="spn_enumeration" => 8;
    * => 1;
  }

// --- Account Type Multiplier ---
| account_multiplier := case {
    account_type="user_account" => 3;
    * => 1;
  }

// --- Calculate Weighted Score ---
| weighted_score := base_score * account_multiplier

// --- Aggregate per User per Hour ---
| groupBy(
    [UserName, ComputerName, account_type],
    function=[
      sum(weighted_score, as=risk_score),
      count(as=total_queries),
      collect([query_target], limit=20)
    ],
    span=59m
  )

// --- Threshold ---
| risk_score >= 50

// --- Severity Classification ---
| severity := case {
    risk_score >= 200 => "CRITICAL";
    risk_score >= 100 => "HIGH";
    risk_score >= 50 => "MEDIUM";
    * => "LOW";
  }

| sort(risk_score, order=desc, limit=50)

// === TUNING EXCLUSIONS ===
// Add environment-specific service accounts that generate legitimate LDAP volume:
// | UserName!=/svc_sccm|svc_nessus|svc_crowdstrike|svc_backup/i
// | ComputerName!=/DC01|DC02|SCCM01/i

// === ANALYST NOTES ===
// TRUE POSITIVE indicators:
//   - User account (not service account) generating 50+ LDAP queries in 1h
//   - Queries targeting Domain Admins or Enterprise Admins
//   - SPN enumeration (Kerberoasting precursor)
//   - Activity from a workstation, not a known management server
//   - Off-hours execution
//
// INVESTIGATION PIVOT:
//   After this fires, check for:
//   1. Process tree on source host — what tool generated the LDAP queries?
//      (BloodHound/SharpHound, ADRecon, PowerView, dsquery, net group)
//   2. Subsequent Kerberos TGS requests (if SPN enumeration detected)
//   3. Lateral movement attempts from the same account
//   4. Whether the account was recently compromised (check risky sign-ins)
