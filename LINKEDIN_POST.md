I open-sourced my detection engineering toolkit.

Over the past several months I've been building CQL detections, Python automation, and threat hunting queries for CrowdStrike Next-Gen SIEM in an enterprise environment. I kept running into the same problem: there aren't many production-tested CQL resources out there, especially for identity threat detection and cross-platform correlation.

So I built a toolkit and put it on GitHub.

What's inside:

— CQL detection rules for identity threats (risky sign-in → MFA manipulation, LDAP recon scoring, brute force correlation), impossible travel with Haversine distance and device fingerprinting, SharePoint bulk download anomaly detection, and persistence/evasion techniques (UAC bypass, browser hijack, scheduled task abuse)

— Python tooling: a MITRE ATT&CK coverage analyzer that maps your deployed detections to the framework and shows you exactly where your gaps are, a hunt query generator that outputs ready-to-paste CQL from technique IDs or IOCs, and a threat intel enrichment pipeline with Haversine-based impossible travel analysis

— 10 ready-to-run hunting queries covering encoded PowerShell, LOLBin download cradles, credential dumping, lateral movement, DNS tunneling, and suspicious process chains

— A complete CQL reference guide built from actual investigation work, not documentation

Every detection includes MITRE ATT&CK mapping, false positive guidance, severity scoring, and analyst investigation notes. Nothing theoretical — every pattern has been validated against real telemetry.

If you're a detection engineer working in CrowdStrike NG-SIEM, migrating from Chronicle or Splunk, or a SOC analyst looking to move into detection engineering, this might save you some time.

Link in comments.

#DetectionEngineering #CrowdStrike #CQL #ThreatHunting #Cybersecurity #MITREATTACK #SIEM #InfoSec
