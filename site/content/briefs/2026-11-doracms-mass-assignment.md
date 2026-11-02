---
brief_id: brief-2026-11-02-doracms-mass-assignment
event_id: brief-2026-11-02-doracms-mass-assignment
revision: 1
activity_at: "2026-11-02T15:51:08Z"
title: 'DoraCMS: Mass assignment in user API key management (CVE-2026-120448)'
slug: 2026-11-doracms-mass-assignment
description: DoraCMS through version 3.1.0 is vulnerable to a mass assignment flaw in the PUT /api/v1/user/api-keys/:id endpoint, allowing authenticated attackers to rebind API keys to other user accounts and perform unauthorized administrative actions.
date: "2026-11-02T15:51:08Z"
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
  validation_status: Source verified
cpes:
  - cpe:2.3:a:doracms:doracms:*:*:*:*:*:*:*:*
tags:
  - mass-assignment
  - privilege-escalation
  - web-application
vendors:
  - DoraCMS
products:
  - DoraCMS (<= 3.1.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can set the userId field on their own key to a victim id, then act as that victim to modify profiles and publish or delete content.
    confidence_band: high
cves:
  - id: CVE-2026-120448
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120448
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch DoraCMS to the latest version to remediate CVE-2026-120448
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-120448 mass assignment vulnerability
  hunt_leads:
    - lead: Identify unusual PUT requests to /api/v1/user/api-keys/ followed by administrative actions
      technique_id: T1068
      data_needed:
        - Web server access logs
        - Application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves PUT requests to /api/v1/user/api-keys/:id
  mitigation_plan:
    - priority: immediate
      action: Upgrade DoraCMS
      owner: IT Operations
      addresses: CVE-2026-120448
      evidence: NVD advisory for CVE-2026-120448
---

DoraCMS through version 3.1.0 contains a mass assignment vulnerability in the PUT /api/v1/user/api-keys/:id endpoint. An authenticated, low-privileged user can manipulate the 'userId' field in a PUT request to associate their own API key with a victim's account. This allows the attacker to impersonate the victim, enabling unauthorized modifications to profiles, content publication, and content deletion.

## Impact
Successful exploitation grants an attacker the privileges of a targeted user, which may include administrative rights depending on the victim's account level. This allows for unauthorized profile changes, as well as the deletion or modification of content within the DoraCMS instance.

## Recommendation
- Update DoraCMS to the latest available version containing the patch for CVE-2026-120448.
- Review web server access logs for anomalous PUT requests directed at the /api/v1/user/api-keys/ endpoint.
- Audit existing API key ownership and monitor for unexpected changes in key-to-user mappings.
