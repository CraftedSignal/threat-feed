---
brief_id: brief-2026-11-03-foxel-auth-bypass
event_id: brief-2026-11-03-foxel-auth-bypass
revision: 1
activity_at: "2026-11-03T18:01:15Z"
title: 'Foxel: Missing authentication and arbitrary file access (CVE-2026-121555)'
slug: 2026-11-foxel-auth-bypass
description: Foxel versions through 2.4.0 contain a missing authentication vulnerability allowing unauthenticated remote attackers to bypass permission checks and retrieve arbitrary files or thumbnails via specific API endpoints.
date: "2026-11-03T18:01:15Z"
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
  - cpe:2.3:a:foxel:foxel:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - file-access
  - webserver
vendors:
  - Foxel
products:
  - Foxel (<= 2.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Foxel through 2.4.0 contains a missing authentication vulnerability that allows unauthenticated attackers to read files
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can supply a VFS mount prefix and relative path to retrieve full file contents or thumbnails
    confidence_band: high
cves:
  - id: CVE-2026-121555
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121555
rules:
  - title: Detect Potential CVE-2026-121555 Exploitation - Unauthenticated File Access
    description: Detects attempts to access Foxel file stream or thumbnail endpoints by unauthenticated users, which may indicate exploitation of CVE-2026-121555.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Scan network for internet-facing Foxel instances.
      owner: SOC
      due: 24h
      evidence: Vulnerability affects public-facing API endpoints.
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block requests to /api/fs/stream and /api/fs/thumb from external IPs.
      owner: IT Operations
      addresses: CVE-2026-121555
      evidence: Vulnerability is exposed via these specific API endpoints.
---

Foxel versions 2.4.0 and earlier are vulnerable to a missing authentication flaw affecting the /api/fs/stream and /api/fs/thumb endpoints. Unauthenticated attackers can exploit this by providing a VFS mount prefix and a relative path, effectively bypassing PathRule permission restrictions. This allows the retrieval of full file contents and thumbnails from the system.

## Impact

Successful exploitation allows unauthenticated remote attackers to read arbitrary files and thumbnails across all VFS mounts, leading to unauthorized information disclosure and potential exposure of sensitive configuration or data stored within the Foxel instance.

## Recommendation

- Identify all internet-facing instances of Foxel version 2.4.0 or earlier.
- Restrict access to the /api/fs/stream and /api/fs/thumb endpoints at the perimeter firewall or reverse proxy level until a vendor-supplied patch is applied.
- Implement monitoring on web server logs to detect unauthorized requests to the identified API endpoints originating from non-trusted IP addresses.
