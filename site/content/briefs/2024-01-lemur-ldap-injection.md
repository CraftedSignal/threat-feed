---
title: Lemur LDAP Filter Injection Vulnerability
slug: 2024-01-lemur-ldap-injection
description: Lemur versions before 1.9.0 are vulnerable to LDAP filter injection, where an authenticated LDAP user can inject LDAP filter metacharacters through the username field to manipulate group membership queries and escalate their privileges to administrator.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ldap
  - injection
  - privilege-escalation
vendors:
  - Netflix
products:
  - Lemur (< 1.9.0)
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-3r34-vq8m-39gh
  - https://cwe.mitre.org/data/definitions/90.html
  - https://owasp.org/www-community/attacks/LDAP_Injection
  - https://www.python-ldap.org/en/python-ldap-3.4.0/reference/ldap-filter.html
rules:
  - title: Detect LDAP Injection Attempts in Lemur Login
    description: Detects suspicious web requests to the /auth/login endpoint containing LDAP filter metacharacters in the username.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect LDAP filter escape bypass via userPrincipalName in network connection logs
    description: Detects bypass of LDAP filter escape characters in userPrincipalName during network connections which could indicate an attempt to perform LDAP injection.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Lemur, a certificate management tool, is vulnerable to LDAP filter injection in versions prior to 1.9.0. The vulnerability resides within the `lemur/auth/ldap.py` module, where user-supplied input from the username field is used to construct LDAP search filters without proper sanitization. Specifically, the `_bind()` method uses Python string interpolation to build LDAP queries based on the provided username. This allows an authenticated LDAP user to inject LDAP filter metacharacters, manipulating group membership queries and potentially escalating their privileges to administrator. Successful exploitation grants unauthorized access to certificates, private keys, and CA configurations.

## Attack Chain

1.  Attacker identifies a Lemur instance with LDAP authentication enabled.
2.  Attacker obtains valid LDAP credentials for a low-privilege user.
3.  The attacker crafts a malicious username containing LDAP filter metacharacters, such as `)(memberOf=CN=LemurAdmins,DC=corp,DC=example,DC=com`.
4.  The attacker sends a `POST /auth/login` request with the crafted username and valid password.
5.  Lemur's `ldap.py` module constructs an LDAP filter using the unsanitized username, resulting in a modified query.
6.  The LDAP server processes the malicious filter, potentially returning unintended group memberships.
7.  Lemur assigns the user the `admin` role based on the manipulated LDAP query results.
8.  The attacker gains unauthorized access to sensitive resources, including certificates, private keys, and CA configurations, and can issue certificates under any authority.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain administrative privileges within Lemur, potentially compromising all managed certificates and associated private keys. The attacker can then issue certificates under any authority, leading to a complete compromise of trust within the affected organization. While the exact number of affected Lemur instances is unknown, this vulnerability poses a significant risk to organizations relying on Lemur for certificate management, particularly those in highly regulated sectors.

## Recommendation

*   Upgrade Lemur to version 1.9.0 or later to patch the LDAP injection vulnerability (CVE-2026-44304).
*   Deploy the provided Sigma rule to detect suspicious process creations with arguments indicative of exploitation attempts.
*   Enable webserver logging to monitor for unusual characters in usernames submitted via POST requests to `/auth/login` to proactively identify potential exploitation attempts.
