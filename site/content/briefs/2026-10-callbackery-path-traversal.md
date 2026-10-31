---
brief_id: brief-2026-10-31-callbackery-path-traversal
event_id: brief-2026-10-31-callbackery-path-traversal
revision: 1
activity_at: "2026-10-31T01:32:01Z"
title: 'CallBackery: Path traversal vulnerability (CVE-2026-118988)'
slug: 2026-10-callbackery-path-traversal
description: CallBackery versions prior to 0.60.1 allow unauthenticated remote attackers to read arbitrary file contents via path traversal in the /doc route.
date: "2026-10-31T01:32:01Z"
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
  validation_status: verified against OSS Security advisory
cpes:
  - cpe:2.3:a:callbackery_project:callbackery:*:*:*:*:*:perl:*:*
tags:
  - webserver
  - path-traversal
  - cve-2026-118988
products:
  - CallBackery (< 0.60.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CallBackery versions before 0.60.1 for Perl let unauthenticated clients read the POD of any file via path traversal in the /doc route
    confidence_band: high
cves:
  - id: CVE-2026-118988
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/447
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade CallBackery to 0.60.1 or later
      owner: IT Operations
      due: 48h
      evidence: OSS Security advisory identifies version 0.60.1 as the fix
  hunt_leads:
    - lead: Detect directory traversal attempts against the /doc endpoint
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability is exploitable via path traversal in the /doc route
  mitigation_plan:
    - priority: immediate
      action: Upgrade to CallBackery 0.60.1
      owner: IT Operations
      addresses: CVE-2026-118988
      evidence: OSS Security advisory
---

A path traversal vulnerability exists in the CallBackery Perl distribution that allows unauthenticated clients to access documentation files outside of the intended directory. This issue affects versions before 0.60.1.

## Impact
Successful exploitation allows an unauthenticated attacker to read the Plain Old Documentation (POD) of arbitrary files on the system, which may disclose sensitive information contained within the source code or documentation files.

## Recommendation
- Update the CallBackery Perl distribution to version 0.60.1 or later immediately.
- Review web server access logs for anomalous requests to the '/doc' URI path containing directory traversal sequences (e.g., '../').
