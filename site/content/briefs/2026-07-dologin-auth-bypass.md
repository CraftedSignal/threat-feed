---
title: 'CVE-2026-14495: DoLogin Security Plugin Authentication Bypass via Insufficient Randomness'
slug: 2026-07-dologin-auth-bypass
description: The DoLogin Security plugin for WordPress, in all versions up to and including 4.3, is vulnerable to authentication bypass (CVE-2026-14495) due to insufficient randomness in magic-link token generation, allowing unauthenticated attackers to brute-force and reconstruct valid passwordless login tokens for any user, including administrators, and gain full control.
date: "2026-07-08T06:23:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - authentication-bypass
  - web-exploitation
  - cve
vendors:
  - DoLogin Security
products:
  - DoLogin Security plugin <= 4.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: an unauthenticated attacker can brute-force the ~10^6-candidate seed space to reconstruct an active passwordless login token
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: authenticate as any targeted user, including administrators, without a password
    confidence_band: high
cves:
  - id: CVE-2026-14495
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14495
---

The DoLogin Security plugin for WordPress, specifically in versions up to and including 4.3, harbors a critical authentication bypass vulnerability, tracked as CVE-2026-14495. This flaw stems from insufficient randomness in the `dologin\s::rrand()` function, which seeds the Mersenne Twister pseudorandom number generator using only the microsecond component of the current time. This constrains the seed space to approximately 10^6 possible values, making the 32-character magic-link tokens generated from it predictable. An unauthenticated attacker can leverage this weakness to brute-force the limited seed space offline, thereby reconstructing active passwordless login tokens. Successful exploitation allows the attacker to authenticate as any targeted user, including administrators, without a password, as the plugin directly calls `wp_set_auth_cookie()` and bypasses standard authentication and lockout mechanisms. Exploitation requires a valid, unexpired passwordless link to exist for the target, and knowledge or guesswork of the numeric user ID.

## Attack Chain

1.  An attacker identifies a WordPress site utilizing the vulnerable DoLogin Security plugin (version <= 4.3).
2.  The attacker identifies a target user (e.g., administrator) and obtains a legitimate, unexpired passwordless login link that was previously generated for this user. This link contains a numeric user ID.
3.  The attacker extracts the numeric user ID from the `?dologin=<id>.<hash>` parameter of the observed link.
4.  The attacker performs an offline brute-force attack against the `mt_srand()` seed space (approximately 10^6 candidates) to reconstruct the `32-character magic-link token` (`<hash>`) corresponding to the target user and link generation time.
5.  The attacker crafts a malicious GET request to the WordPress site, incorporating the target numeric user ID and the successfully reconstructed token in the `?dologin=<id>.<reconstructed_hash>` parameter.
6.  The vulnerable `Pswdless::try_login()` function, registered on the unauthenticated `init` hook, receives and processes this request, comparing the supplied token.
7.  Upon successful verification (due to the reconstructed token), the plugin directly invokes `wp_set_auth_cookie()`, establishing an authenticated session for the attacker as the target user, bypassing standard `wp_authenticate()` and any lockout mechanisms.
8.  The attacker gains full control over the WordPress site if the targeted user possessed administrative privileges.

## Impact

The successful exploitation of CVE-2026-14495 grants unauthenticated attackers complete administrative control over affected WordPress websites. This bypasses all authentication safeguards, allowing attackers to log in as any user, including administrators, without requiring a password. The direct call to `wp_set_auth_cookie()` means that typical login security measures, such as brute-force detection and account lockouts, are bypassed. Consequences include full data exfiltration, website defacement, arbitrary code execution via plugin/theme modifications, introduction of malware, and complete compromise of the web server.

## Recommendation

*   **Patch CVE-2026-14495** immediately by updating the DoLogin Security plugin to a version greater than 4.3 or to the latest available version as provided by the vendor.
*   **Review web server access logs** for unusual or repeated GET requests containing the `dologin` parameter, specifically targeting administrator user IDs.
*   **Implement web application firewall (WAF)** rules to monitor and potentially block requests attempting to exploit CVE-2026-14495, though specific patterns might be difficult to distinguish from legitimate use.
