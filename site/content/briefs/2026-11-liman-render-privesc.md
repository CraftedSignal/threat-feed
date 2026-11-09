---
brief_id: brief-2026-11-09-liman-render-privesc
event_id: brief-2026-11-09-liman-render-privesc
revision: 1
activity_at: "2026-11-09T17:49:37Z"
title: 'HAVELSAN Liman Render Engine: Privilege escalation (CVE-2026-119474)'
slug: 2026-11-liman-render-privesc
description: An incorrect permission assignment vulnerability in HAVELSAN Liman Render Engine versions prior to 1.2-81 allows an attacker to gain elevated privileges.
date: "2026-11-09T17:49:37Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation to identify service-specific execution paths
cpes:
  - cpe:2.3:a:havelsan:liman_render_engine:*:*:*:*:*:*:*:*
vendors:
  - HAVELSAN
products:
  - Liman Render Engine (< 1.2-81)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Incorrect Permission Assignment for Critical Resource vulnerability in HAVELSAN Inc. Liman Render Engine allows Privilege Escalation.
    confidence_band: high
cves:
  - id: CVE-2026-119474
    cvss: 7.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119474
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Liman Render Engine to version 1.2-81 or later.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-119474 vendor advisory
  hunt_leads:
    - lead: Monitor for Liman Render Engine processes spawning unexpected child processes or executing commands with elevated privileges.
      technique_id: T1068
      data_needed:
        - Process creation logs (Event ID 1)
        - Process integrity level changes
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows privilege escalation via incorrect permissions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Liman Render Engine 1.2-81.
      owner: IT Operations
      addresses: CVE-2026-119474
      evidence: NVD disclosure
---

The HAVELSAN Liman Render Engine contains an incorrect permission assignment vulnerability (CVE-2026-119474) that permits local privilege escalation. This vulnerability allows an attacker to gain unauthorized elevated rights on a system where the affected software is installed. The vulnerability affects all versions of Liman Render Engine prior to 1.2-81.

## Impact

Successful exploitation of this vulnerability allows an attacker to escalate privileges on the host system, potentially leading to full system compromise depending on the context in which the service or application is running.

## Recommendation

- Upgrade to HAVELSAN Liman Render Engine version 1.2-81 or later to remediate the permission assignment flaw.
- Review local user and service account permissions on systems hosting Liman Render Engine to ensure the principle of least privilege is enforced until the patch can be applied.
- Audit logs for unexpected process execution from accounts associated with the Liman Render service.
