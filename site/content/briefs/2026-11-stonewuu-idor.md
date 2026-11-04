---
brief_id: brief-2026-11-04-stonewuu-idor
event_id: brief-2026-11-04-stonewuu-idor
revision: 1
activity_at: "2026-11-04T14:47:39Z"
title: Stonewuu ai-fusion-video Insecure Direct Object Reference (CVE-2026-121940)
slug: 2026-11-stonewuu-idor
description: Stonewuu ai-fusion-video versions before 1.3.0 are vulnerable to an IDOR vulnerability in multiple API endpoints, allowing authenticated attackers to perform unauthorized read, modification, and deletion of data via ID enumeration.
date: "2026-11-04T14:47:39Z"
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
  validation_status: Verified against CVE-2026-121940 record
cpes:
  - cpe:2.3:a:stonewuu:ai-fusion-video:*:*:*:*:*:*:*:*
vendors:
  - Stonewuu
products:
  - ai-fusion-video (< 1.3.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1595.002
    technique_name: Vulnerability Scanning
    evidence: Attackers can enumerate auto-increment ids on /api/project, /api/asset and /api/script handlers to read, overwrite, cascade-delete data, and add themselves as project members.
    confidence_band: high
cves:
  - id: CVE-2026-121940
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121940
rules:
  - title: Detect Potential IDOR Enumeration - /api/project, /api/asset, /api/script
    description: Detects potential IDOR enumeration by tracking high volumes of sequential or rapid requests to project-related API handlers by a single authenticated session.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1595.002
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ai-fusion-video to version 1.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-121940 advisory
  hunt_leads:
    - lead: Identify accounts frequently requesting multiple project objects in short windows
      technique_id: T1595.002
      data_needed:
        - Web server logs containing URI stem and source IP
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source document notes ID enumeration on API handlers
  mitigation_plan:
    - priority: immediate
      action: Upgrade ai-fusion-video to 1.3.0
      owner: IT Operations
      addresses: CVE-2026-121940
      evidence: NVD advisory
---

Stonewuu ai-fusion-video before version 1.3.0 contains an insecure direct object reference (IDOR) vulnerability. Authenticated users can access, modify, or delete sensitive project data by manipulating auto-incrementing object IDs in API requests. Successful exploitation enables unauthorized data access, unauthorized data modification/deletion, and unauthorized project membership escalation.

## Impact

Attackers can read, overwrite, and cascade-delete project assets and scripts, as well as add themselves as project members, leading to full compromise of project data integrity and confidentiality.

## Recommendation

- Upgrade Stonewuu ai-fusion-video to version 1.3.0 or later immediately.
- Review access logs for the affected API paths for abnormal patterns indicative of ID enumeration (e.g., sequential ID requests from a single user session).
- Implement rate limiting on API endpoints to mitigate automated enumeration attempts.
