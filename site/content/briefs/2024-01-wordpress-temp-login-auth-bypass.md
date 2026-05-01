---
title: WordPress Temporary Login Plugin Authentication Bypass (CVE-2026-7567)
slug: 2024-01-wordpress-temp-login-auth-bypass
description: The Temporary Login plugin for WordPress versions up to 1.0.0 is vulnerable to authentication bypass due to improper input validation, allowing unauthenticated attackers to log in as arbitrary temporary users by sending a specially crafted GET request.
date: "2026-05-01T10:15:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication bypass
  - wordpress
  - plugin vulnerability
  - cve-2026-7567
  - cloud
vendors:
  - WordPress
products:
  - Temporary Login plugin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7567
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7567
rules:
  - title: Detect WordPress Temporary Login Authentication Bypass Attempt
    description: Detects attempts to exploit CVE-2026-7567 by identifying HTTP requests with array-based 'temp-login-token' parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress Temporary Login Empty Token Authentication Bypass
    description: Detects potential authentication bypass attempts by identifying requests with an empty 'temp-login-token' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-7567 is an authentication bypass vulnerability that affects the Temporary Login plugin for WordPress, specifically versions up to and including 1.0.0. The vulnerability stems from a failure to properly validate the 'temp-login-token' GET parameter within the `maybe_login_temporary_user()` function. By supplying an array as the value for this parameter, attackers can circumvent the intended `empty()` check. This leads to the `sanitize_key()` function returning an empty string, which is then used in a database query to fetch users. WordPress ignores empty `meta_value` parameters, causing the query to return all users with the `_temporary_login_token` meta key. Consequently, an unauthenticated attacker can effectively authenticate as any user with an active temporary login session by sending a single, maliciously crafted GET request. This poses a severe risk to website security, as it allows unauthorized access to user accounts and potentially sensitive data.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the vulnerable Temporary Login plugin (version <= 1.0.0).
2. The attacker crafts a malicious GET request targeting the WordPress site's login endpoint, including the 'temp-login-token' parameter as an array (e.g., `temp-login-token[]=`).
3. The web server receives the GET request.
4. The `maybe_login_temporary_user()` function processes the request.
5. Due to improper input validation, the `empty()` check is bypassed when the 'temp-login-token' parameter is an array.
6. `sanitize_key()` processes the array and returns an empty string as the meta_value.
7. WordPress executes a database query using the empty meta_value, effectively retrieving all users with active temporary login tokens.
8. The attacker is granted unauthorized access to the account of a targeted temporary user, bypassing normal authentication procedures.

## Impact

Successful exploitation of CVE-2026-7567 allows unauthenticated attackers to bypass login restrictions and gain unauthorized access to WordPress user accounts utilizing the vulnerable Temporary Login plugin. The severity is high, as it allows complete compromise of user accounts without requiring any valid credentials. The impact includes potential data theft, account takeover, website defacement, and other malicious activities, depending on the privileges of the compromised user account.

## Recommendation

*   Apply the available patch or upgrade the Temporary Login plugin to a version greater than 1.0.0 to remediate CVE-2026-7567.
*   Deploy the Sigma rule `Detect WordPress Temporary Login Authentication Bypass Attempt` to detect exploitation attempts by monitoring HTTP requests with array-based `temp-login-token` parameters in the query string.
*   Implement input validation on the web server to reject requests containing array-based parameters where scalar strings are expected.
