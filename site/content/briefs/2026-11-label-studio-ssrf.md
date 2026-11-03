---
brief_id: brief-2026-11-03-label-studio-ssrf
event_id: brief-2026-11-03-label-studio-ssrf
revision: 1
activity_at: "2026-11-03T18:01:27Z"
title: 'Label Studio: Server-side request forgery (CVE-2026-121561)'
slug: 2026-11-label-studio-ssrf
description: Label Studio versions prior to 1.23.2 and label-studio-sdk prior to 2.1.2 are vulnerable to SSRF, allowing authenticated users to access internal resources and capture sensitive API tokens.
date: "2026-11-03T18:01:27Z"
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
tags:
  - ssrf
  - web-vulnerability
vendors:
  - Label Studio
products:
  - Label Studio (< 1.23.2)
  - label-studio-sdk (< 2.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Label Studio... contains a server-side request forgery vulnerability that allows authenticated users to read internal URLs through image-bearing export formats.
    confidence_band: high
cves:
  - id: CVE-2026-121561
    cvss: 7.7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121561
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Label Studio to 1.23.2 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerable versions are < 1.23.2 and < 2.1.2.
  hunt_leads:
    - lead: Identify outbound requests from Label Studio servers to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
      technique_id: T1190
      data_needed:
        - VPC Flow Logs
        - Proxy logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can import tasks with data.image pointing at internal services.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Label Studio to 1.23.2 or later.
      owner: IT Operations
      addresses: CVE-2026-121561
      evidence: Official remediation provided via NVD.
---

CVE-2026-121561 affects Label Studio (< 1.23.2) and label-studio-sdk (< 2.1.2). The vulnerability allows an authenticated attacker to perform server-side request forgery (SSRF). By importing tasks with a crafted 'data.image' field, an attacker can coerce the Label Studio server into making unauthorized requests to internal network services. Exporting these tasks via YOLO or COCO formats allows the attacker to retrieve internal service responses, potentially leading to the theft of organization owner API tokens through Host header manipulation.

## Attack Chain

1. Attacker authenticates to the Label Studio platform.
2. Attacker submits a task containing a 'data.image' URL pointing to a targeted internal service.
3. Label Studio server processes the image metadata from the task.
4. Attacker initiates an export request using the YOLO or COCO format.
5. The server performs an SSRF request to the internal URL provided in the task metadata.
6. Attacker retrieves the exported file, which includes the response body from the internal service or captured API tokens.

## Recommendation

- Upgrade Label Studio to version 1.23.2 or later immediately.
- Upgrade label-studio-sdk to version 2.1.2 or later.
- Audit outbound network egress from Label Studio servers to limit access to sensitive internal infrastructure.
