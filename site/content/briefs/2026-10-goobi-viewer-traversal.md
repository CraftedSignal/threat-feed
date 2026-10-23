---
brief_id: brief-2026-10-23-goobi-viewer-traversal
event_id: brief-2026-10-23-goobi-viewer-traversal
revision: 2
activity_at: "2026-10-23T16:39:11Z"
revision_history:
  - revision: 2
    at: "2026-10-23T16:39:11Z"
    checksum: sha256:f6748acad5ce779bd859245e08bec0ebead30ebba49f1636772c388347cf5613
    summary: poc_available
    changed_fields:
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-46652&utm_source=rss&utm_medium=rss
title: 'Goobi viewer: Arbitrary file write and remote code execution (CVE-2026-46652)'
slug: 2026-10-goobi-viewer-traversal
description: Goobi viewer versions 24.03 to 26.04 contain a path traversal vulnerability allowing remote code execution via a malicious Content-Disposition header in external file downloads.
date: "2026-10-23T15:43:28Z"
lastmod: "2026-10-23T16:38:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:goobi:goobi_viewer:24.03:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-46652&utm_source=rss&utm_medium=rss
tags:
  - path-traversal
  - rce
  - web-application
  - cve-2026-46652
vendors:
  - Goobi
products:
  - Goobi viewer (24.03 - 26.04)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: When targeting the deployed web-application directory, this yields remote code execution as the tomcat OS user.
    confidence_band: high
cves:
  - id: CVE-2026-46652
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-46652
  - https://sploitus.com/exploit?id=CVE-2026-46652&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Goobi viewer to version 26.05
      owner: IT Operations
      due: 24h
      evidence: This issue has been patched in version 26.05.
  hunt_leads:
    - lead: Monitor web application logs for unexpected file write attempts containing traversal patterns
      technique_id: T1190
      data_needed:
        - Application audit logs
        - Filesystem monitoring on Tomcat webapp directories
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: allows for an attacker... supply an absolute path or ../ traversal sequences as the filename
  mitigation_plan:
    - priority: immediate
      action: Upgrade Goobi viewer to 26.05
      owner: IT Operations
      addresses: CVE-2026-46652
      evidence: This issue has been patched in version 26.05.
updates:
  - at: "2026-10-23T16:38:36Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-46652&utm_source=rss&utm_medium=rss
---

Goobi viewer versions 24.03 through 26.04 are vulnerable to path traversal via the `ExternalFilesDownloader.getFilename()` component. The application fails to sanitize the filename extracted from the `Content-Disposition` header provided by an external HTTP server, passing it directly to `Path.resolve()`. An attacker controlling an external resource can supply absolute paths or directory traversal sequences (e.g., ../) to write files to arbitrary locations writable by the Tomcat process. Exploitation targeting the web application directory results in remote code execution as the Tomcat user. This vulnerability is addressed in version 26.05.

## Impact
Successful exploitation allows for arbitrary file write on the host filesystem. If the application environment allows, an attacker can achieve remote code execution by overwriting web application files or placing scripts in executable directories.

## Recommendation
- Update Goobi viewer to version 26.05 or later immediately.
- If patching is delayed, restrict outbound network access for the server to prevent fetching content from unauthorized or untrusted remote HTTP servers.
- Review server-side file access logs for unexpected writes occurring in the web application root or configuration directories.
