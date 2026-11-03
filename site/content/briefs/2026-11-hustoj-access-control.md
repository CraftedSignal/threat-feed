---
brief_id: brief-2026-11-03-hustoj-access-control
event_id: brief-2026-11-03-hustoj-access-control
revision: 1
activity_at: "2026-11-03T16:01:12Z"
title: 'HUSTOJ: Incorrect access control in threadadmin.php (CVE-2026-106991)'
slug: 2026-11-hustoj-access-control
description: HUSTOJ versions 24.09.10 through 26.08.19 contain an incorrect access control vulnerability in threadadmin.php that allows any registered user to modify, lock, or delete arbitrary forum threads.
date: "2026-11-03T16:01:12Z"
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
  validation_status: Source corroborated; environment validation required to confirm HUSTOJ versioning and impact
cpes:
  - cpe:2.3:a:hustoj:hustoj:*:*:*:*:*:*:*:*
vendors:
  - HUSTOJ
products:
  - HUSTOJ (>=24.09.10 and <=26.08.19)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The application fails to verify if a logged-in user possesses administrative privileges or authorship before allowing them to modify, delete, lock, or pin forum threads.
    confidence_band: high
cves:
  - id: CVE-2026-106991
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106991
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit HUSTOJ installations to identify version numbers matching the vulnerable range
      owner: IT Operations
      due: 48h
      evidence: Source specifies vulnerable version range 24.09.10 to 26.08.19
  hunt_leads:
    - lead: Identify unauthorized access or excessive activity targeting threadadmin.php
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies threadadmin.php as the vulnerable component allowing unauthorized thread modifications
  mitigation_plan:
    - priority: immediate
      action: Block or restrict access to threadadmin.php at the WAF level for non-privileged accounts
      owner: SOC
      addresses: CVE-2026-106991
      evidence: Vulnerability exists due to missing authorization checks in threadadmin.php
---

HUSTOJ versions 24.09.10 through 26.08.19 are vulnerable to an incorrect access control flaw in 'threadadmin.php'. The application fails to validate user permissions or authorship before performing administrative operations on forum threads. Any authenticated user can delete, lock, or pin threads, including critical administrative announcements.

## Impact

Successful exploitation allows a low-privileged registered user to perform unauthorized administrative actions on the forum, potentially leading to widespread content deletion or forum disruption.

## Recommendation

Inventory all HUSTOJ instances within the environment. Monitor the application for a vendor patch or security update addressing CVE-2026-106991. If a patch is unavailable, restrict public access to the HUSTOJ forum or implement temporary access controls at the web application firewall (WAF) layer to block access to 'threadadmin.php' for non-administrative user roles.
