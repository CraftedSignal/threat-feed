---
title: Budibase Authentication Bypass via Unanchored Regex
slug: 2024-01-budibase-auth-bypass
description: Budibase versions 3.35.3 and earlier are vulnerable to an authentication bypass due to unanchored regular expressions in the public endpoint matcher, allowing unauthenticated attackers to access protected endpoints by manipulating the query string.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - web-application
  - budibase
vendors:
  - Budibase
products:
  - Budibase
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-8783-3wgf-jggf
iocs:
  - type: url
    value: https://budibase-instance/api/global/users/search
  - type: url
    value: https://budibase-instance/api/global/users/search?x=/api/system/status
ioc_counts:
  url: 2
rules:
  - title: Budibase Authentication Bypass Attempt via Query String
    description: Detects attempts to bypass authentication in Budibase by injecting public endpoint paths into the query string of protected endpoints.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Budibase Authentication Bypass Attempt via URL
    description: Detects attempts to bypass authentication in Budibase by accessing a public endpoint through a protected endpoint URL.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Budibase, a low-code platform, is susceptible to an authentication bypass vulnerability affecting versions 3.35.3 and earlier. The vulnerability stems from the `authenticated` middleware's use of unanchored regular expressions when matching public (no-authentication required) endpoint patterns against incoming requests. By appending a public endpoint path as a query parameter to a protected endpoint, an attacker can effectively bypass authentication checks. For instance, a request like `POST /api/global/users/search?x=/api/system/status` circumvents authentication because the regex `/api/system/status` matches within the query string portion of the URL. This flaw allows unauthenticated users to access sensitive data and functionality, potentially leading to significant data breaches and service disruptions. The exposed endpoints, primarily within the `loggedInRoutes` group, lack secondary per-route authentication, making them particularly vulnerable to this bypass.

## Attack Chain

1. The attacker identifies a Budibase instance running a vulnerable version (<= 3.35.3).
2. The attacker crafts a malicious URL targeting a protected endpoint, such as `/api/global/users/search`.
3. The attacker appends a public endpoint path as a query parameter to the protected endpoint URL, for example, `?x=/api/system/status`.
4. The crafted URL is sent to the Budibase server, which processes the request through its `authenticated` middleware.
5. Due to the unanchored regex, the public endpoint pattern matches within the query string of the URL.
6. The `publicEndpoint` flag is set to true, causing the global authentication check to be skipped.
7. The request reaches the targeted protected endpoint without proper authentication.
8. The attacker gains unauthorized access to the endpoint and its associated data, such as user information.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to enumerate all users (including emails, names, roles, and admin/builder status), discover the account holder (instance owner), trigger license refresh, and publish events. The ability to enumerate all users is the most significant risk, as it exposes the entire user directory of the Budibase instance to unauthorized individuals. This vulnerability affects endpoints within the `loggedInRoutes` group, which lack secondary per-route authentication checks, potentially impacting numerous Budibase instances and exposing sensitive user data.

## Recommendation

- Apply the suggested fixes provided in the advisory by patching the Budibase instance to a version greater than 3.35.3 to address the unanchored regex issue (https://github.com/advisories/GHSA-8783-3wgf-jggf).
- Implement a web application firewall (WAF) rule to detect and block requests containing suspicious query parameters that mimic public endpoint paths targeting protected endpoints, mitigating potential exploitation attempts (https://github.com/advisories/GHSA-8783-3wgf-jggf).
- Deploy the Sigma rule to detect connections to protected Budibase endpoints with query parameters that match known public endpoints to proactively identify and investigate potential exploitation attempts.
