---
title: wger Trainer Login Privilege Escalation Vulnerability
slug: 2026-05-wger-privesc
description: A gym trainer in wger (<= 2.5) can escalate privileges to a gym manager by chaining calls to the trainer-login endpoint due to a flawed permission check, as tracked by CVE-2026-43978.
date: "2026-05-14T16:26:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - CVE-2026-43978
vendors:
  - pip
products:
  - wger (<= 2.5)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-9qpr-vc49-hqg2
rules:
  - title: Detect wger Trainer Login Privilege Escalation Attempt
    description: Detects CVE-2026-43978 exploitation — An attacker attempts to exploit the privilege escalation vulnerability by calling the trainer-login endpoint
    platform: sigma
    severity: high
    tactics:
      - cve-2026-43978
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect Multiple Trainer Login Attempts from Same IP
    description: Detects multiple trainer login attempts from the same IP address in a short period, potentially indicating exploitation of CVE-2026-43978.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-43978
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

A privilege escalation vulnerability exists in wger versions 2.5 and earlier, identified as CVE-2026-43978. This flaw allows a gym trainer to escalate their session to a gym manager or general manager account by chaining two calls to the `trainer-login` endpoint. The vulnerability stems from an insufficient permission check in `wger/core/views/user.py`, where the `trainer.identity` session flag bypasses permission checks on subsequent calls to the trainer-login endpoint. This allows the trainer to escalate privileges without proper authorization. The issue was reported on May 14, 2026 and impacts instances of wger version 2.5 and prior.

## Attack Chain

1. An attacker logs in to the wger application as a gym trainer with limited privileges.
2. The trainer initiates a legitimate switch to a lower-privileged user account using the `/en/user/<user_id>/trainer-login` endpoint.
3. Upon successful switch, the application sets the `trainer.identity` flag in the user's session, identifying the original trainer.
4. The attacker, now operating under the context of the lower-privileged user, makes another call to `/en/user/<manager_id>/trainer-login`, this time targeting a gym manager account.
5. Due to the presence of the `trainer.identity` flag, the permission check at `wger/core/views/user.py:169` is bypassed, allowing the trainer-login to proceed without validating if the current user has `gym_trainer` permissions.
6. Because the user is no longer a trainer, the check on line 173 in `wger/core/views/user.py` is not reached, which would normally block escalation to `manage_gym` or `manage_gyms` permissions.
7. The attacker's session is now elevated to that of the gym manager, granting them full administrative privileges.
8. The attacker can now access sensitive data, modify gym settings, and perform other actions as a gym manager.

## Impact

Successful exploitation of this vulnerability (CVE-2026-43978) allows a malicious gym trainer to gain unauthorized access to sensitive information and administrative functions within the wger application. This includes the ability to view member data, modify contracts, manage gym configurations, and access other trainers' and managers' personal information. The attacker can effectively take over the gym manager's account, potentially impacting all gym operations and member data.

## Recommendation

- Apply the patch provided in the advisory to `wger/core/views/user.py` to fix the permission check logic (see the "How to fix" section in the advisory).
- Upgrade wger to a version greater than 2.5 to remediate CVE-2026-43978.
- Deploy the Sigma rule "Detect wger Trainer Login Privilege Escalation Attempt" to your SIEM to detect exploitation attempts.
- Monitor web server logs for unusual activity related to the `/en/user/<user_id>/trainer-login` endpoint, which may indicate attempts to exploit this vulnerability.
