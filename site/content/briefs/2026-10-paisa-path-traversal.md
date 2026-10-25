---
brief_id: brief-2026-10-25-paisa-path-traversal
event_id: brief-2026-10-25-paisa-path-traversal
revision: 1
activity_at: "2026-10-25T12:28:13Z"
title: 'Paisa: Path traversal vulnerability (CVE-2026-116067)'
slug: 2026-10-paisa-path-traversal
description: Paisa versions prior to 0.7.8 contain a path traversal vulnerability in multiple API handlers, allowing unauthenticated attackers to read arbitrary files or delete backups via directory traversal sequences.
date: "2026-10-25T12:28:13Z"
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
  validation_status: Source verified against NVD
cpes:
  - cpe:2.3:a:paisa:paisa:*:*:*:*:*:*:*:*
tags:
  - web-application
  - path-traversal
vendors:
  - Paisa
products:
  - Paisa (< 0.7.8)
cves:
  - id: CVE-2026-116067
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116067
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Paisa to version 0.7.8 or later
      owner: IT Operations
      due: 24h
      evidence: Paisa before 0.7.8 contains a path traversal vulnerability
  hunt_leads:
    - lead: Identify HTTP requests containing directory traversal sequences directed at file or backup management endpoints
      data_needed:
        - Web server access logs or WAF logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can send crafted names to the editor file and delete_backups endpoints to read any server-readable file
  mitigation_plan:
    - priority: immediate
      action: Apply patch 0.7.8
      owner: IT Operations
      addresses: CVE-2026-116067
      evidence: Paisa before 0.7.8 contains a path traversal vulnerability
---

Paisa versions before 0.7.8 contain a path traversal vulnerability in the GetFile, GetSheet, DeleteBackups, and DeleteSheetBackups handlers. This flaw allows unauthenticated attackers to leverage directory traversal sequences (../) in request parameters to access files or delete backup files residing outside the designated journal or sheets directories.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files accessible to the server process and delete backup files, potentially leading to unauthorized data access and loss of recovery capability.

## Recommendation

- Upgrade Paisa to version 0.7.8 or later immediately.
- Review web server access logs for requests containing "../" patterns targeting endpoints related to file and backup management.
