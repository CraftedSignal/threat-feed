---
title: samlify XML Injection Vulnerability Allows Privilege Escalation (CVE-2026-46490)
slug: 2026-05-samlify-xml-injection
description: samlify's template substitution only escapes attribute contexts, leaving values inserted into element text (e.g., `<saml:AttributeValue>`) unescaped, allowing a normal user to inject XML markup into an attribute value and add new `<saml:Attribute>` elements inside the signed assertion, leading to privilege escalation when attributes are used for authorization (CVE-2026-46490).
date: "2026-05-21T17:15:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xml-injection
  - privilege-escalation
  - saml
vendors:
  - npm
products:
  - samlify (< 2.13.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555.004
    technique_name: Credentials on Web Servers
references:
  - https://github.com/advisories/GHSA-34r5-q4jw-r36m
rules:
  - title: Detect Samlify XML Injection Attempt in SAML Response
    description: Detects potential XML injection attempts in SAML responses by looking for injected SAML attributes within AttributeValue tags (CVE-2026-46490).
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
  - title: Detect Samlify XML Injection in AttributeValue via POST Request
    description: Detects CVE-2026-46490 exploitation — HTTP POST request with XML injection attempt in SAML AttributeValue.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability in samlify versions prior to 2.13.0 allows for XML injection in SAML attribute values. The `replaceTagsByValue()` function in `src/libsaml.ts` only escapes placeholders when preceded by a quote (attribute context) but does not escape element text. This allows a normal user to inject arbitrary XML markup into an attribute value (e.g., email, name) and add new `<saml:Attribute>` elements inside the signed assertion. The Identity Provider (IdP) then signs the tampered assertion, and the Service Provider (SP) accepts the injected attributes as trusted. This issue, identified as CVE-2026-46490, enables privilege escalation if attributes are used for authorization decisions.

## Attack Chain

1. An attacker identifies a SAML integration using a vulnerable version of samlify.
2. The attacker crafts a malicious input containing XML markup designed to inject a new attribute (e.g., 'role=admin') into the SAML assertion. This input is typically injected via a user-controlled field such as email or name.
3. The attacker authenticates with the Identity Provider (IdP), triggering the SAML assertion generation process.
4. The IdP's `replaceTagsByValue()` function fails to properly escape the malicious XML markup within the `<saml:AttributeValue>` tag.
5. The IdP signs the tampered SAML assertion, including the attacker-injected attribute.
6. The IdP sends the modified SAML assertion to the Service Provider (SP).
7. The SP uses `sp.parseLoginResponse()` to parse the SAML assertion. Due to the injected attribute being signed by the IdP, the SP trusts the injected attribute.
8. The attacker gains elevated privileges within the SP application because the SP uses the injected attribute (e.g., 'role=admin') for authorization decisions.

## Impact

Successful exploitation of this vulnerability (CVE-2026-46490) allows attackers to escalate privileges within applications that rely on SAML for authentication and authorization. A normal user can inject arbitrary attributes (e.g., `role=admin`) into a signed assertion and have them parsed by `sp.parseLoginResponse()`. This can lead to unauthorized access to sensitive data, modification of critical system settings, or other malicious activities, depending on how the application uses SAML attributes.

## Recommendation

*   Upgrade to samlify version 2.13.0 or later to remediate the XML injection vulnerability (CVE-2026-46490).
*   Implement server-side input validation and sanitization to prevent XML injection in SAML attribute values.
*   Deploy the Sigma rule `Detect Samlify XML Injection Attempt in SAML Response` to detect potential exploitation attempts.
