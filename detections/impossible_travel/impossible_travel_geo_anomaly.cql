// Ward Script - Impossible Travel Detection (Haversine + Velocity)
// Detects geographically impossible login patterns by calculating the great-circle
// distance between consecutive authentications using the Haversine formula, then
// deriving travel velocity. Includes ASN-based exclusions for cloud providers and
// VPNs to reduce false positives from proxied traffic.
// MITRE: T1078 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: VPN usage, cloud proxy services (Zscaler, Netskope), mobile
//   hotspot IP geolocation inaccuracy. Tune ASN exclusions per environment.
// Required Repo: Identity provider logs with geolocation data
// Recommended Window: 24h
// ---
// DETECTION LOGIC:
//   1. Extract consecutive login events per user with geo coordinates
//   2. Calculate Haversine distance between login pairs
//   3. Calculate time delta between events
//   4. Derive velocity (km/h)
//   5. Flag where velocity exceeds physically possible travel speed
//   6. Exclude known cloud/VPN ASNs that cause false geo jumps
// ---
// NOTE ON HAVERSINE IMPLEMENTATION:
//   CQL does not have native trigonometric functions. The Haversine calculation
//   must be approximated or pre-computed via enrichment. Two approaches:
//   
//   APPROACH A (Recommended): Pre-enrich login events with geo data via Python
//   pipeline (see /python/enrichment/), then calculate distance externally and
//   attach as a field before ingestion.
//
//   APPROACH B: Use city/country-level comparison for a simpler but less precise
//   detection. This is the approach shown below.
// ---

// === APPROACH B: Country-Level Impossible Travel ===
// Simpler variant using country codes instead of coordinate math

#repo=<identity_repo>
| eventType=/authentication|sign-in/i
| outcome=/SUCCESS|success/i
| userName=*
| country=*
| sourceIp=*

// Exclude service accounts
| userName!=/^svc[_-]|^SA[_-]/i
| userName!=/\$$/

// === Cloud/VPN ASN Exclusions ===
// Remove events from known cloud providers and VPN services
// that cause false geolocation jumps
// | asn!=/AS13335|AS8075|AS15169|AS16509|AS14618|AS396982/
//   AS13335 = Cloudflare
//   AS8075  = Microsoft Azure
//   AS15169 = Google Cloud
//   AS16509 = Amazon AWS
//   AS14618 = Amazon AWS
//   AS396982 = Google Cloud

// Correlate consecutive logins per user
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
      count(as=login_count),
      distinctCount(country, as=unique_countries),
      collect([country, sourceIp, @timestamp], limit=20),
      min(@timestamp, as=first_login),
      max(@timestamp, as=last_login)
    ],
    span=24h
  )

// Flag users logging in from 2+ countries within the window
| unique_countries >= 2

// Calculate time between first and last event
| time_delta_hours := ((last_login - first_login) / 1000) / 3600

// Flag impossible travel: multiple countries in under 2 hours
// (adjust threshold based on your org's geography)
| time_delta_hours <= 2

| severity := case {
    time_delta_hours <= 0.5 AND unique_countries >= 3 => "CRITICAL";
    time_delta_hours <= 1 => "HIGH";
    time_delta_hours <= 2 => "MEDIUM";
    * => "LOW";
  }

| sort(time_delta_hours, order=asc)


// === APPROACH A: Haversine with Python Pre-Enrichment ===
// For the full coordinate-based detection with precise distance and velocity
// calculation, use the Python enrichment pipeline:
//
//   python python/enrichment/geo_enrichment.py \
//     --input login_events.json \
//     --output enriched_events.json
//
// The enrichment pipeline:
//   1. Resolves IP → lat/lon via MaxMind GeoIP2
//   2. Groups events by user, sorted by timestamp
//   3. Calculates Haversine distance between consecutive logins
//   4. Computes velocity in km/h
//   5. Flags pairs exceeding 900 km/h (commercial flight speed)
//
// Once enriched, the CQL query simplifies to:

// #repo=<enriched_identity_repo>
// | travel_velocity_kmh >= 900
// | is_vpn_asn != true
// | severity := case {
//     travel_velocity_kmh >= 5000 => "CRITICAL";
//     travel_velocity_kmh >= 2000 => "HIGH";
//     travel_velocity_kmh >= 900 => "MEDIUM";
//     * => "LOW";
//   }
// | select([userName, source_country, dest_country, distance_km,
//           travel_velocity_kmh, time_delta_minutes, severity])
// | sort(travel_velocity_kmh, order=desc)


// === ANALYST NOTES ===
// TRUE POSITIVE indicators:
//   - Login from a country where the org has no employees
//   - Velocity exceeding 5000 km/h (physically impossible, not even by plane)
//   - Successful auth from both locations (not just a failed attempt)
//   - Second location login performs sensitive actions (MFA change, file access)
//
// FALSE POSITIVE indicators:
//   - One of the IPs belongs to a cloud proxy (Zscaler, Netskope, etc.)
//   - User is known to use a commercial VPN
//   - IP geolocation resolves to wrong country (common with mobile carriers)
//   - Both logins are from the same ASN (likely same org's infrastructure)
//
// INVESTIGATION PIVOT:
//   1. Check ASN and ISP for both IPs — is either a known proxy/VPN?
//   2. Check device fingerprint — same device ID or different?
//   3. If different devices, check what the anomalous session accessed
//   4. Cross-reference with risky sign-in detection
//   5. Check for MFA bypass or token replay indicators
