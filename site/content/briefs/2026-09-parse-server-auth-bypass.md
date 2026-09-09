---
title: Authentication Bypass in Parse Server LDAP Adapter (CVE-2026-87806)
slug: 2026-09-parse-server-auth-bypass
description: Parse Server versions before 8.6.88 and 9.10.1-alpha.7 contain an authentication bypass vulnerability in the LDAP adapter that allows attackers to perform account takeover via zero-length credentials.
date: "2026-09-09T12:57:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:parseplatform:parse_server:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-87806
  - account-takeover
vendors:
  - Parse Platform
products:
  - Parse Server (<= 8.6.87, >= 9.0.0 < 9.10.1-alpha.7)
cves:
  - id: CVE-2026-87806
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87806
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Parse Server to 8.6.88 or 9.10.1-alpha.7
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-87806 remediation guidance
  mitigation_plan:
    - priority: immediate
      action: Disable unauthenticated simple binds on LDAP directory servers
      owner: Identity Management
      addresses: CVE-2026-87806
      evidence: Source documentation on directory binding configurations
---

Parse Server versions <= 8.6.87 and >= 9.0.0 < 9.10.1-alpha.7 contain a critical authentication bypass vulnerability (CVE-2026-87806) within the built-in LDAP authentication adapter. The vulnerability stems from improper input validation where the adapter fails to verify the presence of a user-supplied password before initiating a bind request to the directory. If an attacker submits a zero-length password, the application proceeds with an LDAP simple bind request. When integrated with directories that support unauthenticated simple binds, such as Active Directory in its default configuration, the directory treats this request as an anonymous bind and returns a success response. Parse Server interprets this success as a valid authentication event, resulting in the issuance of a session token for the target username. This allows unauthenticated attackers who possess knowledge of a valid directory username to gain unauthorized access to the application. This vulnerability does not affect deployments using directories that explicitly reject unauthenticated binds.

## Impact

Successful exploitation leads to full account takeover, allowing attackers to access private user data, modify account configurations, or gain escalated privileges depending on the permissions associated with the targeted directory account. This affects any Parse Server deployment utilizing the affected LDAP authentication adapter in conjunction with permissive directory services.

## Recommendation

* Immediately upgrade Parse Server instances to version 8.6.88 or 9.10.1-alpha.7 to ensure proper enforcement of non-empty password requirements.
* Audit LDAP directory configurations to ensure they are configured to reject unauthenticated simple binds, which serves as a defense-in-depth measure against this class of vulnerability.
* Review application logs for anomalous authentication patterns, specifically frequent successful logins associated with empty credentials or unexpected authentication source behavior.
