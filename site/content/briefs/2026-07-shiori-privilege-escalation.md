---
title: Shiori Privilege Escalation via Account Update Endpoint (CVE-2026-61463)
slug: 2026-07-shiori-privilege-escalation
description: Shiori contains a privilege escalation vulnerability in its account update endpoint that allows authenticated users to exploit this by sending a crafted PATCH request to modify the 'owner' field to 'true' without proper authorization checks, leading to administrative access and full system control.
date: "2026-07-13T18:19:58Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - privilege-escalation
  - vulnerability
  - web-application
vendors:
  - go-shiori
products:
  - Shiori (< 1.8.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'Shiori contains a privilege escalation vulnerability in the account update endpoint that allows authenticated users to modify the owner field without authorization checks. Attackers can escalate to administrator by submitting a crafted PATCH request with owner: true, then re-authenticate to obtain an admin JWT token granting full system access.'
    confidence_band: high
cves:
  - id: CVE-2026-61463
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61463
  - https://github.com/go-shiori/shiori
  - https://github.com/go-shiori/shiori/commit/6c8a7dbc11b131609bfda736b14d61c51f9027b2
  - https://github.com/go-shiori/shiori/issues/1196
  - https://www.vulncheck.com/advisories/shiori-authenticated-privilege-escalation-via-patch-api-v1-auth-account
iocs:
  - type: url
    value: https://github.com/go-shiori/shiori
  - type: url
    value: https://github.com/go-shiori/shiori/commit/6c8a7dbc11b131609bfda736b14d61c51f9027b2
  - type: url
    value: https://github.com/go-shiori/shiori/issues/1196
  - type: url
    value: https://www.vulncheck.com/advisories/shiori-authenticated-privilege-escalation-via-patch-api-v1-auth-account
ioc_counts:
  url: 4
---

CVE-2026-61463 describes a critical privilege escalation vulnerability affecting Shiori, an open-source bookmark manager. This flaw allows any authenticated user to elevate their privileges to that of an administrator. The vulnerability, published on July 13, 2026, resides in the application's account update endpoint, specifically `/api/v1/auth/account`, where inadequate authorization checks fail to prevent the modification of the `owner` field. Attackers can craft a `PATCH` request containing `owner: true` in the request body and, upon successful submission, re-authenticate to receive an administrative JSON Web Token (JWT). This grants them full, unrestricted control over the Shiori instance, posing a significant risk to data integrity and system availability. While active exploitation has not been publicly confirmed, the simplicity of exploitation and high impact make it a severe threat.

## Attack Chain

1. An attacker gains initial authenticated access to a Shiori instance as a regular user.
2. The attacker identifies the insecure account update endpoint `/api/v1/auth/account` that lacks proper authorization controls for privilege modification.
3. A malicious `PATCH` HTTP request is crafted, targeting the identified account update endpoint.
4. The request body is manipulated to include the parameter `owner: true`, indicating an attempt to escalate privileges.
5. The crafted `PATCH` request is sent to the Shiori server, exploiting the vulnerability by bypassing authorization checks.
6. Upon successful modification of the user's `owner` status, the attacker re-authenticates to the Shiori instance.
7. The re-authentication process issues a new JSON Web Token (JWT) that now contains administrative privileges.
8. The attacker uses this newly acquired admin JWT to execute privileged operations, gaining full control over the Shiori application and potentially underlying data.

## Impact

Successful exploitation of CVE-2026-61463 leads to complete compromise of the Shiori instance. An attacker can elevate a standard user account to an administrative one, gaining full control over all stored bookmarks, user accounts, and potentially any data managed by the application. This could result in unauthorized access to sensitive information, data manipulation or deletion, service disruption, or further lateral movement within the hosting environment if other vulnerabilities are present. The impact is critical for organizations using Shiori to manage sensitive or private information, as it compromises data confidentiality, integrity, and availability.

## Recommendation

* Patch CVE-2026-61463 by upgrading Shiori to version 1.8.0 or later immediately, as detailed in the official project references.
* Enable comprehensive logging for your web server and Shiori application to capture full HTTP request methods, URIs (such as `/api/v1/auth/account`), and request bodies (if feasible) to detect suspicious `PATCH` requests that attempt to modify sensitive user attributes like the `owner` field.
