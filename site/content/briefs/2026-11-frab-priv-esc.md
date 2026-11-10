---
brief_id: brief-2026-11-10-frab-priv-esc
event_id: brief-2026-11-10-frab-priv-esc
revision: 1
activity_at: "2026-11-10T02:04:25Z"
title: 'frab: Privilege escalation via conference_users_attributes (CVE-2026-125364)'
slug: 2026-11-frab-priv-esc
description: An authenticated crew user in frab version 0.9.1 and earlier can escalate privileges to an organizer role by manipulating nested attributes in User controller requests.
date: "2026-11-10T02:04:25Z"
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
  - cpe:2.3:a:frab:frab:*:*:*:*:*:*:*:*
tags:
  - web-application
  - privilege-escalation
  - authentication-bypass
vendors:
  - frab
products:
  - frab (<= 0.9.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: frab through 0.9.1 contains a privilege escalation vulnerability that allows authenticated crew user to grant themselves orga roles by submitting unchecked nested conference_users_attributes.
    confidence_band: high
cves:
  - id: CVE-2026-125364
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125364
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all deployments of frab and identify versions 0.9.1 or earlier.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects frab through 0.9.1.
  hunt_leads:
    - lead: Identify authenticated users with crew-level privileges making POST/PATCH requests to /users or conference-specific user management endpoints containing the conference_users_attributes parameter.
      technique_id: T1068
      data_needed:
        - Web application access logs
        - Application request payload logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: 'Attackers can abuse UsersController#update or #create, which skip filter_conference_users.'
  mitigation_plan:
    - priority: immediate
      action: Upgrade frab to a patched version once released.
      owner: IT Operations
      addresses: CVE-2026-125364
      evidence: Vulnerability confirmed in versions <= 0.9.1.
---

The frab conference management system through version 0.9.1 is vulnerable to a privilege escalation flaw. Authenticated users assigned the 'crew' role can exploit the 'conference_users_attributes' parameter within 'UsersController#update' or 'UsersController#create' actions to grant themselves 'orga' (organizer) roles. This occurs because the application fails to apply the 'filter_conference_users' validation to these requests, allowing the user to bypass standard authorization checks. Successful exploitation grants the attacker full management capabilities over events, schedules, reviewers, and crew members for the targeted conference.

## Impact

A successful exploit allows an authenticated 'crew' user to gain unauthorized administrative privileges over any conference within the installation. This leads to full administrative control, including the ability to delete or modify events, alter schedules, and manage sensitive reviewer data.

## Recommendation

1. Inventory all instances of frab in the environment to confirm versioning.
2. Upgrade all instances to a version later than 0.9.1 when a vendor patch is available.
3. Until a patch is applied, implement strict access controls on the 'UsersController#update' and 'UsersController#create' endpoints for any user currently possessing the 'crew' role.
