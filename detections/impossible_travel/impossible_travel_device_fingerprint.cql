// Ward Script - International Self-Join Impossible Travel (Device Fingerprint Enriched)
// Higher-fidelity variant of impossible travel that uses device fingerprinting and
// ISP/ASN attribution to reduce false positives. Instead of simple geo comparison,
// this correlates device identifiers across login pairs to distinguish between
// "same person, different location" (true travel) vs "different person, stolen creds"
// (compromise indicator).
// MITRE: T1078 | Severity: Critical | Author: Ethan Ward | v1.0
// False Positives: Significantly reduced vs basic impossible travel. Remaining FPs:
//   new device registration during legitimate travel, corporate device pools.
// Required Repo: Identity provider logs with device metadata
// Recommended Window: 24h
// ---
// KEY DIFFERENTIATOR:
//   Basic impossible travel asks: "Is this geographically possible?"
//   This variant asks: "Is this geographically possible AND is it a different device?"
//   A different device + impossible travel = much higher confidence of compromise.
// ---

// === DETECTION: Device-Enriched Impossible Travel ===

#repo=<identity_repo>
| eventType=/authentication|sign-in/i
| outcome=/SUCCESS|success/i
| userName=*
| country=*
| sourceIp=*

// Exclude service accounts and machine accounts
| userName!=/^svc[_-]|^SA[_-]/i
| userName!=/\$$/

// === Extract Device Fingerprint Fields ===
// Available fields vary by identity provider:
//   Entra ID: deviceDetail.deviceId, deviceDetail.browser, deviceDetail.operatingSystem
//   Okta: client.device, client.userAgent.os, client.userAgent.browser
// Normalize to common field names:
| device_id := case {
    deviceDetail.deviceId=* => deviceDetail.deviceId;
    client.device=* => client.device;
    * => "unknown";
  }
| device_os := case {
    deviceDetail.operatingSystem=* => deviceDetail.operatingSystem;
    client.userAgent.os=* => client.userAgent.os;
    * => "unknown";
  }
| device_browser := case {
    deviceDetail.browser=* => deviceDetail.browser;
    client.userAgent.browser=* => client.userAgent.browser;
    * => "unknown";
  }

// Build composite device fingerprint
| device_fingerprint := concat([device_id, "|", device_os, "|", device_browser])

// === ASN-Based Cloud/VPN Exclusions ===
// | asn!=/AS13335|AS8075|AS15169|AS16509|AS14618|AS396982/

// === Self-Join: Correlate Login Pairs Per User ===
| selfJoinFilter(
    field=userName,
    where=[
      {country=*},
      {country=*}
    ],
    prefilter=true
  )

| groupBy(
    [userName],
    function=[
      count(as=total_logins),
      distinctCount(country, as=unique_countries),
      distinctCount(device_fingerprint, as=unique_devices),
      distinctCount(sourceIp, as=unique_ips),
      collect([country, sourceIp, device_fingerprint, device_os, @timestamp], limit=20),
      min(@timestamp, as=first_seen),
      max(@timestamp, as=last_seen)
    ],
    span=24h
  )

// === Impossible Travel Criteria ===
// Multiple countries within the window
| unique_countries >= 2

// Time delta
| time_delta_hours := ((last_seen - first_seen) / 1000) / 3600
| time_delta_hours <= 4

// === Confidence Scoring ===
// Higher confidence when device fingerprint differs across locations
| confidence := case {
    unique_devices >= 2 AND time_delta_hours <= 1 => "CRITICAL";
    unique_devices >= 2 AND time_delta_hours <= 2 => "HIGH";
    unique_devices == 1 AND time_delta_hours <= 0.5 => "HIGH";
    unique_devices == 1 AND time_delta_hours <= 2 => "MEDIUM";
    * => "LOW";
  }

// Only alert on HIGH+ confidence
| in(confidence, values=["CRITICAL", "HIGH"])

| sort(time_delta_hours, order=asc)

// === ANALYST NOTES ===
// CRITICAL confidence (different device + impossible travel):
//   This is the highest fidelity signal. A different device fingerprint
//   combined with impossible travel strongly indicates credential compromise.
//   The attacker is using stolen credentials from a different machine.
//
// HIGH confidence (same device + extremely fast travel):
//   Could indicate token theft/replay where the session token is being
//   used from a different network but the device metadata is spoofed
//   or inherited from the stolen token.
//
// DEVICE FINGERPRINT CAVEATS:
//   - device_id = "unknown" is common for non-managed/BYOD devices
//   - Browser user agent strings can be spoofed
//   - The same physical device on different networks will have different IPs
//     but the SAME device_id — this is expected and reduces FPs
//
// ISP/ASN ATTRIBUTION:
//   After alert fires, check ISP for both IPs:
//   - Residential ISP in both countries = higher concern
//   - One is a cloud provider = likely proxy, lower concern
//   - Both are known corporate egress IPs = likely VPN, investigate further
//
// RESPONSE ACTIONS:
//   1. Immediately revoke all sessions for the user
//   2. Require re-authentication with MFA
//   3. Review the anomalous session for data access
//   4. Check for MFA registration changes during the session
//   5. Notify the user to confirm travel status
