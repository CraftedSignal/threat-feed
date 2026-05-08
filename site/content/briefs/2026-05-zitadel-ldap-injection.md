---
title: ZITADEL LDAP Filter Injection Vulnerability in Login Flow
slug: 2026-05-zitadel-ldap-injection
description: ZITADEL's LDAP identity provider implementation fails to properly escape user-provided usernames before incorporating them into LDAP search filters, allowing unauthenticated attackers to perform LDAP Filter Injection to enumerate usernames and extract sensitive attribute data.
date: "2026-05-08T17:11:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ldap-injection
  - information-disclosure
  - zitadel
vendors:
  - ZITADEL
products:
  - ZITADEL (4.0.0 - 4.14.0)
  - ZITADEL (2.71.11 - 2.71.19)
  - ZITADEL (3.1.0 - 3.4.9)
references:
  - https://github.com/advisories/GHSA-rxvx-hhpj-q6px
iocs:
  - type: email
    value: security@zitadel.com
ioc_counts:
  email: 1
rules:
  - title: Detect LDAP Injection Attempts via ZITADEL Login
    description: Detects LDAP injection attempts in ZITADEL login flow by identifying suspicious characters in the username parameter within HTTP requests to the login endpoint.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    data_sources:
      - webserver
  - title: Detect LDAP Injection - Generic Filter Characters
    description: Detects potential LDAP injection attempts by identifying common LDAP filter metacharacters in web requests. This is a generic rule meant to catch a wider range of attacks.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability has been identified in ZITADEL's LDAP identity provider implementation. The application fails to adequately escape user-provided usernames before incorporating them into LDAP search filters during the login process. This flaw enables unauthenticated attackers to perform LDAP Filter Injection, potentially leading to information disclosure. Versions affected include ZITADEL 4.0.0 through 4.14.0, 3.1.0 through 3.4.9, and 2.71.11 through 2.71.19. Successful exploitation allows an attacker to enumerate valid usernames and extract sensitive attribute data from the connected LDAP directory. While a full authentication bypass is not possible, the systematic enumeration of usernames poses a significant risk. The vulnerability was reported by ProScan AppSec.

## Attack Chain

1.  Attacker initiates a login attempt to the ZITADEL instance via the web interface.
2.  The attacker provides a username containing LDAP metacharacters (e.g., `*`, `(`, `)`) crafted to perform LDAP injection.
3.  ZITADEL's LDAP identity provider receives the crafted username without proper sanitization or escaping.
4.  The application incorporates the malicious username into an LDAP search filter.
5.  The crafted LDAP query is executed against the connected LDAP directory.
6.  The LDAP directory processes the malicious query, potentially disclosing information or causing errors.
7.  ZITADEL relays the LDAP response back to the user interface.
8.  The attacker analyzes the success or failure responses to enumerate valid usernames and extract attribute data through blind LDAP injection.

## Impact

Successful exploitation of this vulnerability allows attackers to enumerate valid usernames and extract sensitive attribute data from the connected LDAP directory. This could lead to unauthorized access to sensitive information, privilege escalation, or further attacks against the organization. Although a full authentication bypass is not possible, the information gained through this vulnerability can be used to facilitate other malicious activities. The exact number of affected organizations is currently unknown, but any organization using ZITADEL with LDAP integration within the specified version ranges is potentially at risk.

## Recommendation

*   Upgrade ZITADEL to version 4.15.0 or later, 3.4.10 or later, or 2.71.20 or later to remediate the LDAP injection vulnerability as documented in the advisory.
*   Deploy the Sigma rule "Detect LDAP Injection Attempts via ZITADEL Login" to identify potential exploitation attempts in webserver logs.
*   Monitor webserver logs for suspicious characters in usernames during login attempts that may indicate LDAP injection attempts, as shown in the provided Sigma rule.
*   Review and harden LDAP directory access controls to limit the scope of information disclosure in case of successful exploitation, as recommended in the advisory.
