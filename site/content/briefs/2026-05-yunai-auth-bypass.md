---
title: YunaiV yudao-cloud Authentication Bypass Vulnerability (CVE-2026-7710)
slug: 2026-05-yunai-auth-bypass
description: YunaiV yudao-cloud up to version 3.8.0 is vulnerable to an authentication bypass (CVE-2026-7710) due to improper handling of the mock-token argument in the JwtAuthenticationTokenFilter.java file, allowing remote attackers to bypass authentication.
date: "2026-05-04T00:16:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication bypass
  - cve-2026-7710
  - web application
vendors:
  - YunaiV
products:
  - yudao-cloud <= 3.8.0
  - Ruoyi-Vue-Pro
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7710
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7710
rules:
  - title: Detect Malicious Mock Token Argument
    description: Detects attempts to exploit CVE-2026-7710 by identifying requests containing the 'mock-token' argument in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Mock Token Usage in URI
    description: This rule detects the usage of 'mock-token' within the URI, potentially indicating an attempt to exploit authentication vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-7710 is an authentication bypass vulnerability affecting YunaiV's yudao-cloud, specifically versions up to 3.8.0. The vulnerability resides in the `doFilterInternal` function within the `JwtAuthenticationTokenFilter.java` file of the Ruoyi-Vue-Pro component. An attacker can exploit this vulnerability by manipulating the `mock-token` argument, leading to improper authentication. This allows a remote attacker to potentially gain unauthorized access to the application. Public exploits are available, increasing the risk of exploitation. The vendor was notified but has not responded.

## Attack Chain

1.  Attacker identifies a YunaiV yudao-cloud instance running a vulnerable version (<= 3.8.0).
2.  Attacker crafts a malicious HTTP request targeting an endpoint protected by authentication.
3.  The crafted request includes a manipulated `mock-token` argument designed to bypass the JWT authentication filter.
4.  The `JwtAuthenticationTokenFilter.java` component processes the request and improperly validates the manipulated `mock-token`.
5.  Due to the flawed authentication logic, the attacker is granted unauthorized access as an authenticated user.
6.  Attacker gains access to protected resources and functionalities within the application.
7.  Attacker performs privileged actions such as data modification, account takeover, or further exploitation of the system.

## Impact

Successful exploitation of CVE-2026-7710 allows attackers to bypass authentication and gain unauthorized access to YunaiV yudao-cloud applications. This can lead to the compromise of sensitive data, modification of application settings, and potentially full system takeover. Given the availability of public exploits, organizations using affected versions of yudao-cloud are at high risk. The CVSS v3.1 base score for this vulnerability is 7.3, indicating a high severity level.

## Recommendation

*   Upgrade YunaiV yudao-cloud to a patched version that addresses CVE-2026-7710.
*   Deploy the Sigma rule `Detect Malicious Mock Token Argument` to identify exploitation attempts by monitoring web server logs for the presence of a `mock-token` argument.
*   Implement input validation on the server side to ensure that `mock-token` values conform to expected patterns.
