---
brief_id: brief-2026-11-09-grand-job-bypass
event_id: brief-2026-11-09-grand-job-bypass
revision: 1
activity_at: "2026-11-09T15:51:08Z"
title: 'The Grand Job WordPress plugin: Authentication bypass via password reset (CVE-2026-115237)'
slug: 2026-11-grand-job-bypass
description: The Grand Job WordPress plugin through 1.2.1 contains an authentication bypass vulnerability allowing unauthenticated attackers to reset the passwords of arbitrary users, including administrators.
date: "2026-11-09T15:51:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment validation of the specific plugin URI path.
cpes:
  - cpe:2.3:a:the_grand_job:the_grand_job:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - authentication-bypass
  - cve
products:
  - The Grand Job (<= 1.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: The Grand Job WordPress plugin through 1.2.1 does not correctly verify the password reset code before updating a user's password, allowing unauthenticated attackers to set the password of arbitrary accounts.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: allowing unauthenticated attackers to set the password of arbitrary accounts, including administrators, and fully take over the site.
    confidence_band: high
cves:
  - id: CVE-2026-115237
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115237
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Disable or uninstall The Grand Job plugin on all production WordPress sites.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows full site takeover via unauthenticated password reset.
  hunt_leads:
    - lead: Hunt for suspicious HTTP POST requests targeting WordPress password reset endpoints where the reset token validation is skipped or bypassed.
      technique_id: T1556
      data_needed:
        - Web server access logs (Apache/Nginx)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The plugin fails to correctly verify the reset code, allowing an unauthenticated attacker to reset the password.
  mitigation_plan:
    - priority: immediate
      action: Disable plugin and reset credentials for all administrative accounts if compromise is suspected.
      owner: IT Operations
      addresses: CVE-2026-115237
      evidence: Plugin permits unauthorized password changes for any user account.
---

The Grand Job WordPress plugin (versions 1.2.1 and earlier) fails to properly validate password reset codes during the password reset process. This flaw allows unauthenticated remote attackers to update the passwords of arbitrary user accounts, including those with administrative privileges, leading to full site takeover.

## Impact
Successful exploitation allows for full site compromise by granting the attacker administrative control over the affected WordPress installation.

## Recommendation
- Inventory all WordPress instances utilizing "The Grand Job" plugin.
- Disable or remove the plugin until a patch is released by the developer.
- Audit administrative user account logs for unexpected password changes occurring since the discovery of this vulnerability.
