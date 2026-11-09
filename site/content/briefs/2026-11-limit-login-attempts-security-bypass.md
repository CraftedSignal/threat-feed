---
brief_id: brief-2026-11-09-limit-login-attempts-security-bypass
event_id: brief-2026-11-09-limit-login-attempts-security-bypass
revision: 1
activity_at: "2026-11-09T15:51:24Z"
title: 'Limit Login Attempts Security: Two-factor authentication bypass (CVE-2026-118202)'
slug: 2026-11-limit-login-attempts-security-bypass
description: The Limit Login Attempts Security WordPress plugin before version 3.4.1 allows an attacker with a valid password to bypass 2FA by manipulating request headers.
date: "2026-11-09T15:51:24Z"
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
tags:
  - wordpress
  - authentication-bypass
  - cve-2026-118202
vendors:
  - Limit Login Attempts Security
products:
  - Limit Login Attempts Security (< 3.4.1)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    subtechnique_id: T1556.006
    subtechnique_name: Multi-Factor Authentication
    evidence: The Limit Login Attempts Security WordPress plugin before 3.4.1 does not confirm that its two-factor authentication step succeeded before completing a login and treats a failure to build that step as success
    confidence_band: high
cves:
  - id: CVE-2026-118202
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118202
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Limit Login Attempts Security to version 3.4.1 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-118202 disclosure
  hunt_leads:
    - lead: Identify successful logins for accounts with 2FA where 2FA initialization errors were present in the authentication workflow
      technique_id: T1556.006
      data_needed:
        - WordPress/Webserver access logs
        - Plugin-specific authentication logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The plugin treats a failure to build that step as success
---

The Limit Login Attempts Security plugin for WordPress, in versions prior to 3.4.1, contains a flaw in its two-factor authentication (2FA) logic. The plugin fails to verify the successful completion of the 2FA step, incorrectly treating a failure to initialize the 2FA process as a successful authentication. 

## Impact

An attacker in possession of a valid password for a target account can bypass the second factor of authentication. By sending a specific, malformed request header that disrupts the 2FA mechanism, the attacker is granted unauthorized access to the protected account.

## Recommendation

* Update the Limit Login Attempts Security plugin to version 3.4.1 or later to implement proper validation of the 2FA authentication flow.
* Audit access logs for accounts with 2FA enabled to identify anomalous authentication patterns or failed 2FA initialization attempts that resulted in successful login events.
