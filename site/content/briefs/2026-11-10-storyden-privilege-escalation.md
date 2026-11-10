---
brief_id: brief-2026-11-10-storyden-privilege-escalation
event_id: brief-2026-11-10-storyden-privilege-escalation
revision: 1
activity_at: "2026-11-10T02:02:24Z"
title: 'Storyden: Privilege escalation via role management (CVE-2026-125360)'
slug: 2026-11-10-storyden-privilege-escalation
description: Storyden versions through 1.26.16 contain a privilege escalation vulnerability allowing users with MANAGE_ROLES to assign administrative permissions, leading to full instance takeover.
date: "2026-11-10T02:02:24Z"
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
  - cpe:2.3:a:storyden:storyden:*:*:*:*:*:*:*:*
vendors:
  - Storyden
products:
  - Storyden (<= 1.26.16)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Storyden through 1.26.16 contains a privilege escalation vulnerability that allows users holding MANAGE_ROLES to grant the ADMINISTRATOR permission without being administrators.
    confidence_band: high
cves:
  - id: CVE-2026-125360
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125360
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit role assignment logs for accounts being granted the ADMINISTRATOR permission
      owner: SOC
      due: 24h
      evidence: Attackers can call AccountAddRole on another controlled account or use RoleCreate and RoleUpdate to create administrator roles
  hunt_leads:
    - lead: Identify accounts that were granted ADMINISTRATOR status by users who were not previously administrators
      technique_id: T1068
      data_needed:
        - Application audit logs for RoleCreate, RoleUpdate, and AccountAddRole events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can call AccountAddRole on another controlled account or use RoleCreate and RoleUpdate
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the latest patched version of Storyden
      owner: IT Operations
      addresses: CVE-2026-125360
      evidence: Storyden through 1.26.16 contains a privilege escalation vulnerability
---

Storyden through version 1.26.16 contains a privilege escalation vulnerability. Users assigned the MANAGE_ROLES permission can leverage the AccountAddRole, RoleCreate, or RoleUpdate functions to assign the ADMINISTRATOR permission to any account, including their own. This results in unauthorized administrative access and potential full control over the application instance.

## Impact

Successful exploitation allows for complete instance takeover by an account initially possessing only the MANAGE_ROLES permission.

## Recommendation

* Update Storyden to the latest version immediately to remediate the privilege escalation flaw.
* Review all existing account role assignments and creation logs for evidence of unauthorized role elevation.
* Restrict the assignment of the MANAGE_ROLES permission to trusted users until the application is patched.
