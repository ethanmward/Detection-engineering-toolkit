// Ward Script - Risky Sign-In Followed by MFA Enrollment Change
// Correlates a risky sign-in event with a subsequent MFA enrollment
// modification within a configurable time window. Detects adversary-in-the-middle
// (AiTM) attacks where a compromised session is used to register a new MFA method
// for persistent access.
// MITRE: T1078.004, T1556.006 | Severity: Critical | Author: Ethan Ward | v1.0
// False Positives: New employee onboarding, legitimate MFA resets by helpdesk.
//   Tune by excluding known helpdesk service accounts and onboarding OUs.
// Required Repo: Varies (Entra ID / identity provider logs)
// Recommended Window: 24h (correlation window is 15h internal)
// ---
// DETECTION LOGIC OVERVIEW:
// 1. Identify risky sign-in events (medium/high risk level from identity provider)
// 2. Identify MFA registration or modification events
// 3. Self-join on user principal name within a 15-hour window
// 4. Flag cases where MFA change follows risky sign-in (not precedes)
// 5. Enrich with device fingerprint and IP geolocation for analyst context
// ---

// === PHASE 1: Risky Sign-In Events ===
// Adapt #repo and field names to your identity provider integration
// Example below uses Microsoft Entra ID via Graph API

#repo=<identity_repo>
| #event_simpleName=UserRiskEvent OR @sourcetype=/entra|azuread|graph/i
| riskLevel=/medium|high/i
| riskState!=/dismissed|remediated/i
| userPrincipalName=*
| rename(field=userPrincipalName, as=upn)
| rename(field=@timestamp, as=risk_time)
| rename(field=ipAddress, as=risk_ip)
| rename(field=riskLevel, as=risk_severity)
| select([upn, risk_time, risk_ip, risk_severity, riskEventType])

// === PHASE 2: MFA Registration/Modification Events ===

#repo=<identity_repo>
| #event_simpleName=MfaRegistration OR operationType=/Add|Update/i
| targetResource=/StrongAuthentication|MicrosoftAuthenticator|PhoneNumber|FIDO2/i
| userPrincipalName=*
| rename(field=userPrincipalName, as=upn)
| rename(field=@timestamp, as=mfa_time)
| rename(field=ipAddress, as=mfa_ip)
| select([upn, mfa_time, mfa_ip, operationType, targetResource])

// === PHASE 3: Correlation via selfJoinFilter ===
// Join risky sign-in with MFA change on same user within 15h window

#repo=<identity_repo>
| (riskLevel=/medium|high/i AND riskState!=/dismissed|remediated/i)
  OR (operationType=/Add|Update/i AND targetResource=/StrongAuthentication|MicrosoftAuthenticator|PhoneNumber|FIDO2/i)
| userPrincipalName=*
| selfJoinFilter(
    field=userPrincipalName,
    where=[
      {riskLevel=/medium|high/i},
      {operationType=/Add|Update/i}
    ],
    prefilter=true
  )
| groupBy(
    [userPrincipalName],
    function=[
      count(),
      min(@timestamp, as=first_event),
      max(@timestamp, as=last_event),
      collect([riskLevel, operationType, ipAddress, targetResource], limit=10)
    ]
  )
| window_hours := ((last_event - first_event) / 1000) / 3600
| window_hours <= 15
| sort(window_hours, order=asc)

// === ANALYST NOTES ===
// TRUE POSITIVE indicators:
//   - Risk event type is "unfamiliarFeatures" or "anomalousToken"
//   - MFA registration IP differs from risky sign-in IP
//   - MFA method added is Authenticator app or phone (not FIDO2 from IT)
//   - User is not in onboarding OU or new hire list
//
// FALSE POSITIVE indicators:
//   - Helpdesk service account performed the MFA reset
//   - User submitted a ticket requesting MFA change
//   - Risk was auto-remediated by Conditional Access policy
//
// RESPONSE ACTIONS:
//   1. Revoke all active sessions for the user
//   2. Reset MFA registration (remove the newly added method)
//   3. Force password reset
//   4. Review sign-in logs for the compromised session
//   5. Check for mail forwarding rules or inbox rule changes
