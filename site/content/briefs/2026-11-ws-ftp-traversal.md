---
brief_id: brief-2026-11-09-ws-ftp-traversal
event_id: brief-2026-11-09-ws-ftp-traversal
revision: 1
activity_at: "2026-11-09T19:57:07Z"
title: 'Progress Software WS_FTP Server: Path traversal in Thin Client Web Transfer (CVE-2026-115341)'
slug: 2026-11-ws-ftp-traversal
description: An improper access restriction vulnerability in the Thin Client Web Transfer component of Progress Software WS_FTP Server allows authenticated users to perform unauthorized path traversal to access files outside their intended scope.
date: "2026-11-09T19:57:07Z"
type: advisory
types:
  - advisory
severities:
  - high
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
  - cpe:2.3:a:progress:ws_ftp_server:*:*:*:*:*:*:*:*
tags:
  - web-application
  - path-traversal
  - windows
vendors:
  - Progress Software
products:
  - WS_FTP Server (< 2025.0.5)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Improper access restrictions... could allow an authenticated FTP user to access files outside their intended scope.
    confidence_band: high
cves:
  - id: CVE-2026-115341
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115341
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Progress Software WS_FTP Server to 2025.0.5 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability in Thin Client Web Transfer component of Progress Software WS_FTP Server versions prior to 2025.0.5
  hunt_leads:
    - lead: Hunt for directory traversal sequences within application logs for the Thin Client Web Transfer component
      technique_id: T1083
      data_needed:
        - WS_FTP Server application access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Improper access restrictions... could allow an authenticated FTP user to access files outside their intended scope.
  mitigation_plan:
    - priority: immediate
      action: Apply patch 2025.0.5 to all WS_FTP Server instances
      owner: IT Operations
      addresses: CVE-2026-115341
      evidence: Progress Software WS_FTP Server versions prior to 2025.0.5
---

Progress Software WS_FTP Server versions prior to 2025.0.5 contain a vulnerability in the Thin Client Web Transfer component. An authenticated user can exploit improper access restrictions to access files outside of their designated directory boundaries. This vulnerability is assigned CVE-2026-115341.

## Impact

Authenticated attackers may gain unauthorized access to sensitive files on the underlying Windows filesystem that are otherwise restricted by the application configuration.

## Recommendation

Update Progress Software WS_FTP Server to version 2025.0.5 or later. Organizations should monitor Thin Client Web Transfer logs for directory traversal patterns such as "../" sequences in request paths from authenticated user sessions.
