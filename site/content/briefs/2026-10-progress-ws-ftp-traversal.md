---
brief_id: brief-2026-10-29-progress-ws-ftp-traversal
event_id: brief-2026-10-29-progress-ws-ftp-traversal
revision: 1
activity_at: "2026-10-29T17:50:25Z"
title: 'Progress Software WS_FTP Server: Path Traversal in Ad Hoc Transfer (CVE-2026-84294)'
slug: 2026-10-progress-ws-ftp-traversal
description: An authenticated path traversal vulnerability in the Ad Hoc Transfer component of Progress Software WS_FTP Server allows unauthorized access to files outside of intended directories.
date: "2026-10-29T17:50:25Z"
lastmod: "2026-10-29T17:50:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against NVD metadata.
cpes:
  - cpe:2.3:a:progress:ws_ftp_server:*:*:*:*:*:*:*:*
  - cpe:2.3:a:progress_software:ws_ftp_server:*:*:*:*:*:*:*:*
tags:
  - path-traversal
  - file-access
  - windows
vendors:
  - Progress Software
products:
  - WS_FTP Server (< 2024.0.6, < 2025.0.3)
  - WS_FTP Server (prior to 2024.0.6 and 2025.0.3)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: An authenticated user can exploit this flaw to read files outside of the intended directory structure.
    confidence_band: high
cves:
  - id: CVE-2026-84294
    cvss: 7.7
    kev_status: "false"
  - id: CVE-2026-84295
    cvss: 10
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84294
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84295
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch WS_FTP Server to 2024.0.6 or 2025.0.3
      owner: IT Operations
      due: 48h
      evidence: Source specifies vulnerability in versions prior to 2024.0.6 and 2025.0.3.
  hunt_leads:
    - lead: Search for path traversal sequences in application-level logs for WS_FTP Ad Hoc Transfer
      technique_id: T1083
      data_needed:
        - WS_FTP Server application request logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows unauthorized file access via path manipulation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to fixed versions
      owner: IT Operations
      addresses: CVE-2026-84294
      evidence: NVD advisory for CVE-2026-84294
updates:
  - at: "2026-10-29T17:50:35Z"
    level: L3
    summary: severity → critical; added CVE-2026-84295
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84295
---

Progress Software WS_FTP Server versions prior to 2024.0.6 and 2025.0.3 are vulnerable to a path traversal issue (CVE-2026-84294) located in the Ad Hoc Transfer component. An authenticated attacker can manipulate pathnames to access files residing outside the intended directory structure on the underlying Windows host.

## Impact

Successful exploitation allows an authenticated user to perform unauthorized file system reads, potentially resulting in the disclosure of sensitive configuration files, user data, or system information.

## Recommendation

* Immediately upgrade WS_FTP Server to version 2024.0.6 or 2025.0.3 to remediate CVE-2026-84294.
* Review access logs for the Ad Hoc Transfer component for abnormal directory traversal characters (e.g., '..\\', '../') in requests from authenticated users.
* Restrict access to the Ad Hoc Transfer module to the minimum set of necessary users until patching is completed.
