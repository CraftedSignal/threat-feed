---
brief_id: brief-2026-10-29-wordpress-2fa-bypass
event_id: brief-2026-10-29-wordpress-2fa-bypass
revision: 1
activity_at: "2026-10-29T13:18:54Z"
title: 'WordPress: Two Factor Authentication and AIOS MFA bypass (CVE-2026-111739)'
slug: 2026-10-wordpress-2fa-bypass
description: A session hijacking vulnerability in Two Factor Authentication and All-In-One Security (AIOS) WordPress plugins allows attackers to bypass MFA by providing their own valid 2FA code during a victim's login process.
date: "2026-10-29T13:18:54Z"
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
  validation_status: Source verified; standard patch management required.
cpes:
  - cpe:2.3:a:two_factor_authentication_project:two_factor_authentication:*:*:*:*:*:wordpress:*:*
  - cpe:2.3:a:all_in_one_security_and_firewall_project:all_in_one_security_and_firewall:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - authentication-bypass
  - wordpress
products:
  - Two Factor Authentication (< 1.17.0)
  - All-In-One Security (AIOS) (< 5.5.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    subtechnique_id: T1550.001
    subtechnique_name: Application Access Token
    evidence: allowing an attacker who knows a victim's password and holds their own two-factor-enabled account to satisfy the victim's second-factor check with their own code and obtain the victim's session.
    confidence_band: high
cves:
  - id: CVE-2026-111739
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111739
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade vulnerable WordPress plugins to the specified fixed versions.
      owner: IT Operations
      due: 48h
      evidence: Two Factor Authentication plugin before 1.17.0, All-In-One Security (AIOS) WordPress plugin before 5.5.0
  hunt_leads:
    - lead: Identify anomalies in WordPress login audit logs where authentication requests for multiple users originate from the same source IP or share session artifacts within short timeframes.
      technique_id: T1550.001
      data_needed:
        - WordPress Application Logs (login, session start)
        - Web Server access logs (Source IP, User-Agent)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An attacker who knows a victim's password and holds their own two-factor-enabled account to satisfy the victim's second-factor check.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugins
      owner: IT Operations
      addresses: CVE-2026-111739
      evidence: Source NVD advisory
---

The Two Factor Authentication plugin (prior to 1.17.0) and the All-In-One Security (AIOS) plugin (prior to 5.5.0) for WordPress contain an authentication flaw. The plugins fail to bind the two-factor authentication (2FA) verification process to the specific user account undergoing authentication. An attacker possessing both a victim's password and a separate, attacker-controlled 2FA-enabled account can satisfy the victim's MFA challenge by submitting their own 2FA token, resulting in the hijacking of the victim's session.

## Impact
Successful exploitation grants an attacker unauthorized access to a victim's account, allowing for potential session hijacking and takeover of administrative or user accounts.

## Recommendation
- Update the "Two Factor Authentication" plugin to version 1.17.0 or later.
- Update the "All-In-One Security (AIOS)" plugin to version 5.5.0 or later.
- Review WordPress authentication logs for concurrent or unusual login patterns where a single 2FA device or session identifier appears associated with multiple disparate user account authentication attempts.
