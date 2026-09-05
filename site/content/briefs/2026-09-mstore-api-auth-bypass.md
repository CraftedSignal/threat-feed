---
title: Authentication Bypass in Mstore Api Plugin for WordPress via JWT Forgery
slug: 2026-09-mstore-api-auth-bypass
description: The Mstore Api plugin for WordPress (<= 4.20.0) is vulnerable to authentication bypass via JWT forgery, allowing unauthenticated attackers to impersonate any user by crafting illegitimate Firebase Phone Auth tokens.
date: "2026-09-05T07:29:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mstore:mstore_api:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - cve
  - authentication-bypass
  - web-application
vendors:
  - Mstore
products:
  - Mstore Api (<= 4.20.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Mstore Api plugin for WordPress is vulnerable to Authentication Bypass via JWT Forgery in versions up to, and including, 4.20.0
    confidence_band: high
cves:
  - id: CVE-2026-13447
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13447
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Mstore Api plugin to a version patched against CVE-2026-13447
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-13447 vulnerability in Mstore Api <= 4.20.0
  mitigation_plan:
    - priority: immediate
      action: Disable Mstore Api plugin if patching is not immediately feasible
      owner: IT Operations
      addresses: CVE-2026-13447
      evidence: Plugin is vulnerable to authentication bypass
---

The Mstore Api plugin for WordPress is susceptible to an authentication bypass vulnerability, tracked as CVE-2026-13447, affecting all versions up to and including 4.20.0. The vulnerability resides in the FirebasePhoneAuthHelper::verify_id_token() function, which is responsible for validating Firebase identity tokens. The implementation properly decodes JWT claims such as 'alg', 'kid', 'aud', and 'iss', but completely fails to perform cryptographic signature verification. Specifically, the function neglects to call openssl_verify() or utilize any mechanism to validate the token against Google's public key infrastructure. Consequently, an unauthenticated attacker can supply a forged JWT signed with a custom RSA key pair, effectively bypassing authentication checks. This allows for unauthorized access to existing WordPress user accounts associated with specific phone numbers or the creation of new, arbitrary accounts with elevated privileges.

## Attack Chain

1. Attacker identifies a WordPress site utilizing the Mstore Api plugin version 4.20.0 or earlier.
2. Attacker interacts with the plugin authentication endpoint that triggers the FirebasePhoneAuthHelper::verify_id_token() function.
3. Attacker generates a custom RSA key pair to sign a malicious JWT.
4. Attacker constructs a forged JWT with claims matching the target user or arbitrary account details.
5. Attacker transmits the forged JWT to the vulnerable plugin endpoint.
6. The plugin logic decodes the provided JWT and validates claims, but skips signature verification, accepting the forged token as valid.
7. The plugin grants the attacker an authenticated session context for the impersonated identity.
8. Attacker gains unauthorized access to the victim's account data or account creation functionality.

## Impact

Successful exploitation enables unauthenticated remote attackers to bypass identity verification, leading to account takeover or the unauthorized creation of arbitrary user accounts. This grants attackers access to sensitive user data and administrative functions within the WordPress environment. The 9.8 CVSS score reflects the high potential for full compromise of user accounts and the relative ease of generating forged tokens due to the total absence of cryptographic validation.

## Recommendation

* Immediately update the Mstore Api plugin to the latest available version beyond 4.20.0 to remediate CVE-2026-13447.
* Audit access logs for suspicious account authentication patterns or unexpected account creations tied to phone-based registration workflows.
* If the latest patch cannot be applied, disable the plugin to eliminate the vulnerable endpoint from the attack surface.
