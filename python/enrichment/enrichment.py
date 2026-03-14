"""
Threat Intelligence Enrichment Pipeline
Enriches IPs, domains, and user agents against threat intel APIs.
Supports AbuseIPDB, VirusTotal, and Shodan. Outputs structured JSON
for SIEM correlation or analyst review.

Also includes geo-enrichment for impossible travel detection:
resolves IP addresses to coordinates and calculates Haversine distance
and travel velocity between consecutive login events.

Author: Ethan Ward
Version: 1.0

Usage:
  # Enrich a list of IPs
  python enrichment.py enrich-ip --input indicators.txt --output enriched.json

  # Enrich login events for impossible travel analysis
  python enrichment.py geo-enrich --input login_events.json --output travel_analysis.json

  # Enrich a single IOC
  python enrichment.py lookup --type ip --value 185.220.101.1
"""

import json
import csv
import math
import argparse
import os
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

# Optional imports — gracefully handle missing packages
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ============================================================
# Configuration
# ============================================================

# API keys loaded from environment variables
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")

# Rate limiting (requests per minute)
RATE_LIMITS = {
    "abuseipdb": 60,
    "virustotal": 4,  # Free tier
    "shodan": 10,
}


# ============================================================
# Haversine Distance Calculation
# ============================================================

def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculate the great-circle distance between two points on Earth
    using the Haversine formula.

    Args:
        lat1, lon1: Latitude and longitude of point 1 (degrees)
        lat2, lon2: Latitude and longitude of point 2 (degrees)

    Returns:
        Distance in kilometers
    """
    R = 6371  # Earth's radius in kilometers

    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c


def calculate_travel_velocity(
    distance_km: float, time_delta_seconds: float
) -> float:
    """
    Calculate travel velocity in km/h.

    Args:
        distance_km: Distance between two points in kilometers
        time_delta_seconds: Time between events in seconds

    Returns:
        Velocity in km/h. Returns 0 if time_delta is 0.
    """
    if time_delta_seconds <= 0:
        return 0.0
    hours = time_delta_seconds / 3600
    return distance_km / hours


# ============================================================
# Geo-Enrichment for Impossible Travel
# ============================================================

def analyze_login_travel(events: list) -> list:
    """
    Analyze a list of login events for impossible travel.

    Each event should have:
      - userName: string
      - timestamp: epoch seconds or ISO string
      - sourceIp: string
      - latitude: float
      - longitude: float
      - country: string (optional)
      - city: string (optional)

    Returns a list of travel analysis results with distance and velocity.
    """
    # Group events by user
    user_events = {}
    for event in events:
        user = event.get("userName", "unknown")
        if user not in user_events:
            user_events[user] = []
        user_events[user].append(event)

    results = []

    for user, user_logins in user_events.items():
        # Sort by timestamp
        user_logins.sort(key=lambda x: x.get("timestamp", 0))

        # Compare consecutive pairs
        for i in range(1, len(user_logins)):
            prev = user_logins[i - 1]
            curr = user_logins[i]

            lat1 = prev.get("latitude", 0)
            lon1 = prev.get("longitude", 0)
            lat2 = curr.get("latitude", 0)
            lon2 = curr.get("longitude", 0)

            # Skip if coordinates are missing
            if not all([lat1, lon1, lat2, lon2]):
                continue

            distance_km = haversine_distance(lat1, lon1, lat2, lon2)

            # Calculate time delta
            t1 = prev.get("timestamp", 0)
            t2 = curr.get("timestamp", 0)
            time_delta_seconds = t2 - t1

            velocity_kmh = calculate_travel_velocity(distance_km, time_delta_seconds)

            # Classify travel feasibility
            if velocity_kmh > 5000:
                classification = "IMPOSSIBLE"
                severity = "CRITICAL"
            elif velocity_kmh > 900:
                classification = "SUSPICIOUS"
                severity = "HIGH"
            elif velocity_kmh > 500:
                classification = "UNLIKELY"
                severity = "MEDIUM"
            else:
                classification = "FEASIBLE"
                severity = "LOW"

            result = {
                "userName": user,
                "event_1": {
                    "timestamp": t1,
                    "sourceIp": prev.get("sourceIp", ""),
                    "country": prev.get("country", ""),
                    "city": prev.get("city", ""),
                    "latitude": lat1,
                    "longitude": lon1,
                },
                "event_2": {
                    "timestamp": t2,
                    "sourceIp": curr.get("sourceIp", ""),
                    "country": curr.get("country", ""),
                    "city": curr.get("city", ""),
                    "latitude": lat2,
                    "longitude": lon2,
                },
                "analysis": {
                    "distance_km": round(distance_km, 2),
                    "time_delta_seconds": time_delta_seconds,
                    "time_delta_minutes": round(time_delta_seconds / 60, 2),
                    "velocity_kmh": round(velocity_kmh, 2),
                    "classification": classification,
                    "severity": severity,
                },
            }

            results.append(result)

    # Sort by velocity descending (most suspicious first)
    results.sort(key=lambda x: x["analysis"]["velocity_kmh"], reverse=True)
    return results


# ============================================================
# Threat Intel API Enrichment
# ============================================================

def enrich_ip_abuseipdb(ip: str) -> Optional[dict]:
    """Query AbuseIPDB for IP reputation data."""
    if not HAS_REQUESTS or not ABUSEIPDB_KEY:
        return None

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": True,
            },
            timeout=10,
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "source": "abuseipdb",
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "is_tor": data.get("isTor", False),
                "last_reported": data.get("lastReportedAt", ""),
            }
    except Exception as e:
        print(f"  [!] AbuseIPDB error for {ip}: {e}")
    return None


def enrich_ip_virustotal(ip: str) -> Optional[dict]:
    """Query VirusTotal for IP analysis."""
    if not HAS_REQUESTS or not VIRUSTOTAL_KEY:
        return None

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_KEY},
            timeout=10,
        )
        if response.status_code == 200:
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "ip": ip,
                "malicious_detections": stats.get("malicious", 0),
                "suspicious_detections": stats.get("suspicious", 0),
                "harmless_detections": stats.get("harmless", 0),
                "as_owner": attrs.get("as_owner", ""),
                "asn": attrs.get("asn", 0),
                "country": attrs.get("country", ""),
                "reputation": attrs.get("reputation", 0),
            }
    except Exception as e:
        print(f"  [!] VirusTotal error for {ip}: {e}")
    return None


def enrich_ip_shodan(ip: str) -> Optional[dict]:
    """Query Shodan for host information."""
    if not HAS_REQUESTS or not SHODAN_KEY:
        return None

    try:
        response = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_KEY},
            timeout=10,
        )
        if response.status_code == 200:
            data = response.json()
            return {
                "source": "shodan",
                "ip": ip,
                "open_ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "os": data.get("os", ""),
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
                "vulns": data.get("vulns", []),
            }
    except Exception as e:
        print(f"  [!] Shodan error for {ip}: {e}")
    return None


def enrich_ip(ip: str) -> dict:
    """Enrich an IP address against all available threat intel sources."""
    enrichment = {
        "ip": ip,
        "enriched_at": datetime.now(tz=__import__("datetime").timezone.utc).isoformat() + "Z",
        "sources": {},
        "risk_score": 0,
        "risk_level": "UNKNOWN",
    }

    # Query each source
    abuseipdb = enrich_ip_abuseipdb(ip)
    if abuseipdb:
        enrichment["sources"]["abuseipdb"] = abuseipdb

    virustotal = enrich_ip_virustotal(ip)
    if virustotal:
        enrichment["sources"]["virustotal"] = virustotal

    shodan = enrich_ip_shodan(ip)
    if shodan:
        enrichment["sources"]["shodan"] = shodan

    # Calculate composite risk score
    score = 0
    if abuseipdb:
        score += abuseipdb.get("abuse_confidence_score", 0) * 0.4
        if abuseipdb.get("is_tor"):
            score += 20
    if virustotal:
        score += virustotal.get("malicious_detections", 0) * 2
        score += virustotal.get("suspicious_detections", 0) * 1
    if shodan:
        if shodan.get("vulns"):
            score += len(shodan["vulns"]) * 5

    enrichment["risk_score"] = min(round(score, 1), 100)
    enrichment["risk_level"] = (
        "CRITICAL" if score >= 80 else
        "HIGH" if score >= 60 else
        "MEDIUM" if score >= 30 else
        "LOW"
    )

    return enrichment


# ============================================================
# CLI Interface
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Enrichment Pipeline"
    )
    subparsers = parser.add_subparsers(dest="command")

    # IP enrichment
    ip_parser = subparsers.add_parser("enrich-ip", help="Enrich IP addresses from file")
    ip_parser.add_argument("--input", required=True, help="File with IPs (one per line)")
    ip_parser.add_argument("--output", required=True, help="Output JSON file")

    # Geo enrichment for impossible travel
    geo_parser = subparsers.add_parser("geo-enrich", help="Analyze login events for impossible travel")
    geo_parser.add_argument("--input", required=True, help="JSON file with login events")
    geo_parser.add_argument("--output", required=True, help="Output JSON file")
    geo_parser.add_argument("--velocity-threshold", type=float, default=900,
                           help="Velocity threshold in km/h (default: 900)")

    # Single lookup
    lookup_parser = subparsers.add_parser("lookup", help="Look up a single IOC")
    lookup_parser.add_argument("--type", required=True, choices=["ip"])
    lookup_parser.add_argument("--value", required=True)

    args = parser.parse_args()

    if args.command == "enrich-ip":
        ips = Path(args.input).read_text().strip().splitlines()
        ips = [ip.strip() for ip in ips if ip.strip()]
        print(f"\n[*] Enriching {len(ips)} IP addresses...\n")

        results = []
        for i, ip in enumerate(ips):
            print(f"  [{i+1}/{len(ips)}] {ip}")
            result = enrich_ip(ip)
            results.append(result)
            time.sleep(1)  # Rate limiting

        Path(args.output).write_text(json.dumps(results, indent=2))
        print(f"\n[+] Results saved to {args.output}")

        # Summary
        high_risk = [r for r in results if r["risk_level"] in ("HIGH", "CRITICAL")]
        print(f"[+] High/Critical risk IPs: {len(high_risk)}/{len(results)}")

    elif args.command == "geo-enrich":
        events = json.loads(Path(args.input).read_text())
        print(f"\n[*] Analyzing {len(events)} login events for impossible travel...\n")

        results = analyze_login_travel(events)

        # Filter by threshold
        flagged = [r for r in results
                   if r["analysis"]["velocity_kmh"] >= args.velocity_threshold]

        output = {
            "analysis_timestamp": datetime.now(tz=__import__("datetime").timezone.utc).isoformat() + "Z",
            "total_events_analyzed": len(events),
            "total_travel_pairs": len(results),
            "flagged_impossible_travel": len(flagged),
            "velocity_threshold_kmh": args.velocity_threshold,
            "results": flagged,
        }

        Path(args.output).write_text(json.dumps(output, indent=2))
        print(f"[+] Flagged {len(flagged)} impossible travel events")
        print(f"[+] Results saved to {args.output}")

        # Print summary
        for r in flagged[:10]:
            print(
                f"  [{r['analysis']['severity']}] {r['userName']}: "
                f"{r['event_1']['country']} → {r['event_2']['country']} | "
                f"{r['analysis']['distance_km']} km in "
                f"{r['analysis']['time_delta_minutes']} min | "
                f"{r['analysis']['velocity_kmh']} km/h"
            )

    elif args.command == "lookup":
        if args.type == "ip":
            result = enrich_ip(args.value)
            print(json.dumps(result, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
