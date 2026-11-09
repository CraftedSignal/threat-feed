---
brief_id: brief-2026-11-09-post-duplicator-privilege-escalation
event_id: brief-2026-11-09-post-duplicator-privilege-escalation
revision: 1
activity_at: "2026-11-09T15:51:34Z"
title: 'Post Duplicator: Privilege escalation via role capability validation flaw (CVE-2026-121875)'
slug: 2026-11-post-duplicator-privilege-escalation
description: The Post Duplicator WordPress plugin fails to validate role capabilities, allowing site administrators on multisite networks to elevate privileges to Super Admin status.
date: "2026-11-09T15:51:34Z"
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
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:post_duplicator:post_duplicator:*:*:*:*:*:wordpress:*:*
products:
  - Post Duplicator (< 3.0.18)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This flaw allows a site administrator on a multisite network who is not a Super Admin to grant any role arbitrary capabilities, including the network-management capabilities reserved to the Super Admin.
    confidence_band: high
cves:
  - id: CVE-2026-121875
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121875
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Post Duplicator to version 3.0.18 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability addressed in version 3.0.18
  hunt_leads:
    - lead: Identify unauthorized role privilege escalation in multisite WordPress installations
      technique_id: T1068
      data_needed:
        - WordPress database logs (wp_user_roles or wp_capabilities)
        - Audit logs capturing admin-level modifications to role settings
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Site administrators can assign network-management capabilities to roles
  mitigation_plan:
    - priority: immediate
      action: Upgrade Post Duplicator to 3.0.18
      owner: IT Operations
      addresses: CVE-2026-121875
      evidence: NVD disclosure
---

The Post Duplicator WordPress plugin versions prior to 3.0.18 contain a vulnerability where role capabilities are not properly validated within the permissions settings. This flaw allows a standard site administrator in a multisite WordPress environment to assign administrative or network-management capabilities to arbitrary roles. This effectively enables privilege escalation to the Super Admin level, bypassing intended security boundaries.

## Impact

Successful exploitation allows a low-privileged site administrator to gain unauthorized administrative control over the entire WordPress multisite network, including the ability to manage network settings, install plugins, and modify user access.

## Recommendation

* Update the Post Duplicator plugin to version 3.0.18 or later immediately to address the missing capability validation.
* Audit existing role assignments in WordPress multisite networks for unexpected modifications, specifically checking for roles granted administrative permissions that should not have them.
* Review administrative logs for changes to role capabilities performed by non-Super Admin users.
