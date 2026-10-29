---
brief_id: brief-2026-10-29-wild-apricot-plugin-bypass
event_id: brief-2026-10-29-wild-apricot-plugin-bypass
revision: 1
activity_at: "2026-10-29T05:03:16Z"
title: 'Wild Apricot Login: Authentication bypass via SSO account binding (CVE-2026-93757)'
slug: 2026-10-wild-apricot-plugin-bypass
description: The Wild Apricot Login plugin for WordPress (<= 1.0.18) is vulnerable to authentication bypass where attackers can hijack administrative sessions by binding malicious WildApricot accounts to existing WordPress user emails via insecure SSO account mapping.
date: "2026-10-29T05:03:16Z"
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
  - cpe:2.3:a:wildapricot:wild_apricot_login:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - sso
  - authentication-bypass
  - cve-2026-93757
vendors:
  - Wild Apricot
products:
  - Wild Apricot Login (<= 1.0.18)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: Attackers... obtain a valid network-global authentication cookie for the victim without their credentials.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550.001
    technique_name: Application Access Token
    evidence: This makes it possible for attackers with custom-level WildApricot membership access to authenticate as an existing WordPress subsite administrator... obtaining a valid network-global authentication cookie for the victim.
    confidence_band: high
cves:
  - id: CVE-2026-93757
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93757
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Wild Apricot Login plugin on all WordPress sites to a version greater than 1.0.18.
      owner: IT Operations
      due: 24h
      evidence: Vulnerable in all versions up to, and including, 1.0.18.
  hunt_leads:
    - lead: Identify successful administrative logins attributed to the Wild Apricot SSO flow that do not match known administrator contact-IDs.
      technique_id: T1550.001
      data_needed:
        - WordPress authentication logs
        - Plugin activity logs
        - Multisite user metadata
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The plugin falls back to a network-global get_user_by(email) lookup... then Controller::login issues a session cookie.
  mitigation_plan:
    - priority: immediate
      action: Disable the Wild Apricot Login plugin if patching is not immediately feasible.
      owner: IT Operations
      addresses: CVE-2026-93757
      evidence: Authentication bypass via SSO Email-Collision Account Binding.
---

CVE-2026-93757 affects the Wild Apricot Login plugin for WordPress in versions up to and including 1.0.18. The vulnerability resides in `Module.php` and `UserSynchronizer::syncWaContact()`, where the plugin incorrectly binds incoming SSO requests to existing WordPress users using an email-only lookup (`get_user_by('email', ...)`) if no specific contact-ID mapping exists. Because this process lacks validation (such as password checks or confirmation), an attacker can authenticate as a victim by registering a WildApricot account with the target's email address and initiating the SSO flow. This allows unauthorized access, particularly in WordPress Multisite environments where session cookies are network-global.

## Impact

Successful exploitation allows an unauthenticated attacker to impersonate any WordPress user, including administrators, without requiring knowledge of the victim's credentials. In a WordPress Multisite installation, this grants administrative access across the entire network.

## Recommendation

* Update the Wild Apricot Login plugin to the latest version immediately.
* Identify and audit all WordPress installations utilizing the Wild Apricot Login plugin.
* Monitor WordPress authentication logs for suspicious administrative logins occurring via SSO or unexpected account binding activity.
* Review administrative user lists on WordPress Multisite networks for unauthorized account modifications or unknown administrative users.
