---
title: code100x Mobile API Authentication Bypass Vulnerability (CVE-2026-8890)
slug: 2026-05-code100x-auth-bypass
description: code100x Mobile API contains an authentication bypass vulnerability (CVE-2026-8890) allowing unauthenticated attackers to impersonate arbitrary users by crafting a JSON payload in the 'g' HTTP header, skipping identity header validation and granting unauthorized access to course data.
date: "2026-05-26T19:19:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - mobile-api
  - cve-2026-8890
  - credential-access
  - privilege-escalation
vendors:
  - code100x
products:
  - code100x Mobile API
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8890
  - CVE-2026-8890
rules:
  - title: Detect code100x Mobile API Authentication Bypass Attempt
    description: Detects CVE-2026-8890 exploitation attempt — monitors for HTTP requests with both 'Auth-Key' and 'g' headers, which indicates a potential authentication bypass attempt in the code100x Mobile API.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
  - title: Detect code100x Mobile API Authentication Bypass Attempt - Crafted g Header
    description: Detects CVE-2026-8890 exploitation attempt — Identifies crafted 'g' header containing JSON-like syntax which suggests attempts to inject spoofed user identities in code100x Mobile API.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
rules_count: 2
---

An authentication bypass vulnerability exists within the code100x Mobile API. This flaw, identified as CVE-2026-8890, allows unauthenticated attackers to impersonate arbitrary users, including administrators. The vulnerability stems from insufficient validation of the 'Auth-Key' HTTP header within the middleware.ts file. By supplying a crafted JSON payload within the 'g' HTTP header, an attacker can bypass authentication and inject a spoofed user identity header. This spoofed identity is then accepted as trusted by the downstream route handler, leading to unauthorized access to course data and other sensitive information. This issue poses a significant risk to user privacy and data security, potentially enabling attackers to access, modify, or delete user accounts and course content.

## Attack Chain

1.  The attacker crafts a malicious HTTP request targeting the Mobile API.
2.  The request includes an 'Auth-Key' header with an arbitrary value to trigger the bypass condition.
3.  The request also includes a 'g' HTTP header containing a crafted JSON payload with the attacker's desired user identity.
4.  The middleware in middleware.ts skips identity header generation due to the presence of the 'Auth-Key' header.
5.  The crafted JSON payload in the 'g' header is used to create a spoofed user identity header.
6.  The downstream route handler, such as the mobile courses endpoint, trusts the spoofed user identity header.
7.  The attacker gains unauthorized access to course data, impersonating the targeted user or administrator.
8.  The attacker can then perform actions as the impersonated user, such as viewing, modifying, or deleting course data.

## Impact

Successful exploitation of CVE-2026-8890 allows unauthenticated attackers to impersonate any user, including administrators, within the code100x Mobile API. This could lead to unauthorized access to sensitive course data, modification of user accounts, and potential disruption of services. The vulnerability poses a significant risk to the confidentiality, integrity, and availability of the platform. The specific number of affected users is currently unknown, but all users of the code100x Mobile API are potentially at risk.

## Recommendation

*   Apply the patch or update provided by code100x to address CVE-2026-8890 to remediate the authentication bypass vulnerability.
*   Deploy the Sigma rule `Detect code100x Mobile API Authentication Bypass Attempt` to identify exploitation attempts based on the presence of the 'Auth-Key' header and a crafted 'g' header.
*   Monitor web server logs for HTTP requests containing the 'Auth-Key' header in combination with a 'g' header, focusing on requests targeting the Mobile API endpoints, as indicated by the rule `Detect code100x Mobile API Authentication Bypass Attempt`.
