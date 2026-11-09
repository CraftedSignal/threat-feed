---
brief_id: brief-2026-11-09-limit-login-attempts-2fa-bypass
event_id: brief-2026-11-09-limit-login-attempts-2fa-bypass
revision: 1
activity_at: "2026-11-09T15:51:19Z"
title: 'Limit Login Attempts Security: Two-factor authentication bypass (CVE-2026-118201)'
slug: 2026-11-limit-login-attempts-2fa-bypass
description: The Limit Login Attempts Security WordPress plugin fails to enforce two-factor authentication (2FA) across all authentication routes, allowing attackers with known passwords to bypass MFA via alternative login interfaces.
date: "2026-11-09T15:51:19Z"
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
  - cpe:2.3:a:limit_login_attempts_reloaded:limit_login_attempts_security:*:*:*:*:*:wordpress:*:*
vendors:
  - Limit Login Attempts Reloaded
products:
  - Limit Login Attempts Security (< 3.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110
    technique_name: Brute Force
    subtechnique_id: T1110.001
    subtechnique_name: Password Guessing
    evidence: an attacker who already knows a protected user's password can authenticate through an alternative login interface and obtain that user's access without completing the second factor.
    confidence_band: high
cves:
  - id: CVE-2026-118201
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118201
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade the Limit Login Attempts Security plugin to version 3.4.1 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-118201 remediation requires updating to version 3.4.1
  hunt_leads:
    - lead: Identify authentication traffic to non-standard or alternative WordPress login endpoints
      technique_id: T1110.001
      data_needed:
        - webserver access logs
        - application audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability exists because 2FA is not enforced on every password-authentication route.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Limit Login Attempts Security to version 3.4.1
      owner: IT Operations
      addresses: CVE-2026-118201
      evidence: Plugin update version 3.4.1 addresses the 2FA enforcement issue.
---

The Limit Login Attempts Security WordPress plugin versions prior to 3.4.1 contain a vulnerability where 2FA enforcement is inconsistent across different password-authentication routes. An attacker possessing valid user credentials can leverage an alternative login interface to authenticate without completing the 2FA challenge, leading to unauthorized access. This issue is identified as CVE-2026-118201.

## Impact

Successful exploitation allows an attacker to bypass 2FA protections, granting them unauthorized access to the application using valid credentials.

## Recommendation

- Upgrade the Limit Login Attempts Security plugin to version 3.4.1 or later immediately.
- Review WordPress application access logs for anomalous authentication patterns or frequent login attempts from unfamiliar interfaces.
- Audit accounts with 2FA enabled to ensure the plugin's security configurations are actively enforced and not bypassed by secondary or alternative login entry points.
