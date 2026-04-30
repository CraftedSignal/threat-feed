---
title: Admidio Inverted 2FA Reset Allows Privilege Escalation
slug: 2024-01-admidio-2fa-bypass
description: A logic error in Admidio's two-factor authentication reset inverts the authorization check, allowing non-admin users to remove other users' TOTP, including administrators, reducing their security to password-only authentication in versions 5.0.8 and earlier.
date: "2024-01-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - 2fa
  - bypass
  - privilege-escalation
  - admidio
vendors:
  - composer
  - admidio
products:
  - admidio
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/advisories/GHSA-rh3w-4ccx-prf9
rules:
  - title: Detect Admidio 2FA Reset Request
    description: Detects suspicious POST requests to the Admidio 2FA reset endpoint, potentially indicating an attempt to exploit the vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Admidio Error Response to 2FA Reset
    description: Detects the 'SYS_NO_RIGHTS' error response when attempting to reset own 2FA, indicating the vulnerability is present and the user lacks necessary permissions.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Admidio, a web-based content management system for organizations, contains a critical vulnerability in its two-factor authentication (2FA) reset mechanism. The vulnerability, present in versions 5.0.8 and earlier, stems from an inverted authorization check within the `modules/profile/two_factor_authentication.php` script. This flaw enables non-administrative users, specifically group leaders with profile edit rights, to disable 2FA for other users, including administrator accounts. The vulnerability was reported on April 29, 2026. By exploiting this flaw, attackers can bypass 2FA, gaining unauthorized access to privileged accounts and potentially compromising the entire Admidio installation. This highlights the importance of rigorous security audits and proper authorization checks in web applications.

## Attack Chain

1. An attacker compromises or gains access to a non-admin user account within Admidio that possesses `hasRightEditProfile()` permission over an administrator account.
2. The attacker crafts a POST request to `/adm_program/modules/profile/two_factor_authentication.php` with the `mode` parameter set to `reset` and the `user_uuid` parameter set to the UUID of the target administrator account.
3. The server-side script `modules/profile/two_factor_authentication.php` executes the flawed authorization check at line 84. Due to the inverted logic (`!==` instead of `===`), the check incorrectly grants permission to the non-admin user to reset the administrator's 2FA.
4. The server removes the TOTP configuration associated with the administrator's account from the database or configuration files.
5. The attacker can now attempt to log in to the administrator account using only the password, bypassing the 2FA requirement.
6. If the attacker knows or can guess the administrator's password (via credential stuffing, brute force, or other means), they successfully gain access to the account.
7. With administrator privileges, the attacker can perform a variety of malicious actions, such as creating new accounts, modifying website content, or accessing sensitive data.

## Impact

The vulnerability allows attackers to bypass two-factor authentication on administrator accounts in Admidio installations. This can lead to unauthorized access to sensitive data, modification of website content, and potentially full control over the affected system. While the number of affected installations is unknown, organizations using vulnerable versions of Admidio are at risk. Success of the attack results in complete compromise of the Admidio instance and the data it manages.

## Recommendation

*   Apply the recommended fix by changing `!==` to `===` on line 84 of `modules/profile/two_factor_authentication.php` to correct the authorization logic (see Overview).
*   Deploy the Sigma rule `Detect Admidio 2FA Reset Request` to detect attempts to exploit this vulnerability by monitoring HTTP POST requests to the vulnerable endpoint (see Rules).
*   Upgrade Admidio to a patched version that incorporates the fix for CVE-2026-41660.
