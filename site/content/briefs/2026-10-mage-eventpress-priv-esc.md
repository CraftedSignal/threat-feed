---
brief_id: brief-2026-10-28-mage-eventpress-priv-esc
event_id: brief-2026-10-28-mage-eventpress-priv-esc
revision: 1
activity_at: "2026-10-28T08:27:05Z"
title: 'Mage Eventpress: Privilege escalation via mep_grant_shop_manager_access (CVE-2026-109381)'
slug: 2026-10-mage-eventpress-priv-esc
description: The Mage Eventpress WordPress plugin is vulnerable to privilege escalation in versions 5.7.8 and earlier due to improper request parameter validation in the mep_grant_shop_manager_access function.
date: "2026-10-28T08:27:05Z"
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
  validation_status: Ready for deployment in lab environment.
cpes:
  - cpe:2.3:a:mage:eventpress:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - privilege-escalation
  - webserver
vendors:
  - Mage
products:
  - Eventpress (<= 5.7.8)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This makes it possible for authenticated attackers, with Shop Manager-level access and above, to elevate their privileges to Administrator.
    confidence_band: high
cves:
  - id: CVE-2026-109381
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109381
rules:
  - title: Detect CVE-2026-109381 Exploitation - Privileged Access Attempt
    description: Detects requests to administrative WordPress pages containing the Eventpress plugin specific GET parameters, which may indicate an attempt to exploit the mep_grant_shop_manager_access privilege escalation vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Mage Eventpress plugin to a version > 5.7.8
      owner: IT Operations
      due: 48h
      evidence: Vulnerable in versions up to, and including, 5.7.8
  hunt_leads:
    - lead: Search logs for unauthorized administrative access by accounts with Shop Manager roles.
      technique_id: T1068
      data_needed:
        - WordPress user role assignment logs
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker elevates privileges to Administrator by appending ?page=mep_x to core admin URLs.
  mitigation_plan:
    - priority: immediate
      action: Update Eventpress plugin to patched version
      owner: IT Operations
      addresses: CVE-2026-109381
      evidence: Plugin vulnerable up to and including 5.7.8
---

The Mage Eventpress plugin for WordPress (versions 5.7.8 and earlier) contains a flaw in the `mep_grant_shop_manager_access()` function. This function hooks into `user_has_cap` and unconditionally grants the `manage_options` capability to users when a request parameter (specifically `$_GET['page']`) begins with 'mep_' or 'mpwem_'. Because this parameter is not validated against registered plugin screens, authenticated users with Shop Manager-level access can elevate their privileges to Administrator by appending malicious parameters to administrative URL paths.

## Impact
Successful exploitation allows authenticated attackers with Shop Manager privileges to achieve full Administrator access, resulting in complete control over the WordPress instance.

## Recommendation
- Update the Mage Eventpress plugin to the latest patched version immediately.
- Audit existing administrator accounts for unauthorized additions or modifications if the plugin was installed during the period of exposure.
- Implement access control monitoring for administrative role assignments within the WordPress environment.
