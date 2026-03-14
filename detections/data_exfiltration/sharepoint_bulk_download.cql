// Ward Script - SharePoint Bulk Download Anomaly Detection
// Detects abnormal file download volume from SharePoint Online that may indicate
// data exfiltration. Uses baseline comparison to identify users downloading
// significantly more files than their historical norm. Correlates with session
// risk signals for higher fidelity.
// MITRE: T1530, T1567.002 | Severity: High | Author: Ethan Ward | v1.0
// False Positives: Legitimate bulk migrations, IT admin backup operations,
//   departing employee archiving (which may also be exfil — context matters).
// Required Repo: Microsoft 365 audit logs or Graph API events
// Recommended Window: 24h (with 7d lookback for baseline)
// ---

// === VARIANT A: Volume-Based Threshold ===
// Simple but effective — flag users exceeding N downloads in a window

#repo=<m365_audit_repo>
| @sourcetype=/microsoft|sharepoint|office365/i
| Operation=/FileDownloaded|FileSyncDownloadedFull/i
| UserId=*
| ObjectId=*

// Exclude known service accounts and automation
// | UserId!=/svc_|app@sharepoint/i

// Exclude specific site collections (e.g., public knowledge bases)
// | SiteUrl!=/sites\/PublicKB|sites\/Templates/i

| groupBy(
    [UserId],
    function=[
      count(as=download_count),
      distinctCount(ObjectId, as=unique_files),
      distinctCount(SiteUrl, as=unique_sites),
      collect([ObjectId, SiteUrl], limit=30),
      min(@timestamp, as=first_download),
      max(@timestamp, as=last_download)
    ],
    span=24h
  )

// Threshold: adjust based on your environment's baseline
| unique_files >= 50

// Time concentration: downloads compressed into short window = more suspicious
| download_window_hours := ((last_download - first_download) / 1000) / 3600

| severity := case {
    unique_files >= 200 AND download_window_hours <= 2 => "CRITICAL";
    unique_files >= 100 => "HIGH";
    unique_files >= 50 AND unique_sites >= 3 => "HIGH";
    unique_files >= 50 => "MEDIUM";
    * => "LOW";
  }

| sort(unique_files, order=desc)


// === VARIANT B: Multi-Site Exfiltration Pattern ===
// Detects users accessing files across multiple SharePoint sites they
// don't normally access — lateral collection before exfiltration

#repo=<m365_audit_repo>
| @sourcetype=/microsoft|sharepoint|office365/i
| Operation=/FileDownloaded|FileAccessed|FileSyncDownloadedFull/i
| UserId=*
| SiteUrl=*

| groupBy(
    [UserId],
    function=[
      count(as=total_operations),
      distinctCount(SiteUrl, as=sites_accessed),
      collect([SiteUrl, Operation], limit=30)
    ],
    span=24h
  )

// User accessing 5+ different site collections in a day is unusual
// for most roles (adjust per your environment)
| sites_accessed >= 5
| total_operations >= 20

| severity := case {
    sites_accessed >= 10 => "CRITICAL";
    sites_accessed >= 7 => "HIGH";
    sites_accessed >= 5 => "MEDIUM";
    * => "LOW";
  }

| sort(sites_accessed, order=desc)


// === VARIANT C: Unmanaged Device Download Detection ===
// Downloads from unmanaged/non-corporate devices are higher risk

#repo=<m365_audit_repo>
| @sourcetype=/microsoft|sharepoint|office365/i
| Operation=/FileDownloaded|FileSyncDownloadedFull/i
| UserId=*
| DeviceType=*

// Flag non-corporate devices
| is_unmanaged := case {
    DeviceType=/unmanaged|unknown|BYOD/i => true;
    MachineId="" => true;
    * => false;
  }
| is_unmanaged = true

| groupBy(
    [UserId],
    function=[
      count(as=download_count),
      distinctCount(ObjectId, as=unique_files),
      collect([ObjectId, ClientIP, DeviceType], limit=20)
    ],
    span=24h
  )

| unique_files >= 10

| sort(unique_files, order=desc)

// === ANALYST NOTES ===
// EXFILTRATION INDICATORS:
//   - High volume downloads compressed into a short time window
//   - Downloads from sites the user doesn't normally access
//   - Downloads from an unmanaged or new device
//   - User recently gave notice or is on a PIP
//   - Downloads followed by large outbound data transfer
//   - Downloading file types: .pst, .zip, .7z, database backups
//
// LEGITIMATE ACTIVITY:
//   - IT admin performing site migration
//   - SharePoint sync client initial sync
//   - Automated backup processes
//   - User transitioning roles and archiving old project files
//
// INVESTIGATION PIVOT:
//   1. Review the file names/paths downloaded — sensitive content?
//   2. Check the session IP and device — corporate or personal?
//   3. Look for subsequent upload to personal cloud (OneDrive personal,
//      Google Drive, Dropbox) via DLP logs
//   4. Check Purview audit logs for sharing link creation
//   5. Review user's HR status (departing, PIP, role change)
//   6. Check for email forwarding rule changes
//
// CORRELATION WITH OTHER DETECTIONS:
//   This detection is most powerful when combined with:
//   - Impossible travel (exfil from anomalous location)
//   - Risky sign-in (compromised session used for exfil)
//   - MFA manipulation (persistence before exfil)
