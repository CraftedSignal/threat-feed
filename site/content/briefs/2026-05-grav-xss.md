---
title: Grav CMS Stored XSS Vulnerability via Unquoted Event Attributes
slug: 2026-05-grav-xss
description: A stored Cross-Site Scripting (XSS) vulnerability in Grav CMS allows publisher-level accounts to execute arbitrary JavaScript due to a blacklist bypass in the detectXss() function when handling unquoted HTML event attributes, leading to session hijacking and unauthorized actions.
date: "2026-05-05T21:30:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - web-application
  - grav
vendors:
  - Grav
products:
  - grav < 2.0.0-beta.2
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-9695-8fr9-hw5q
rules:
  - title: Detect Grav CMS XSS via Unquoted Event Attributes
    description: Detects potential XSS attacks in Grav CMS by identifying unquoted HTML event attributes in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
  - title: Detect Grav CMS XSS Exploit Attempt via Base64 Encoded Payload
    description: Detects attempts to exploit Grav CMS XSS vulnerabilities using base64 encoded JavaScript payloads.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stored Cross-Site Scripting (XSS) vulnerability has been identified in Grav CMS, affecting versions prior to 2.0.0-beta.2. The vulnerability resides in the `detectXss()` function within the Grav core, which is responsible for sanitizing user-supplied input. A flawed regular expression allows attackers with publisher-level privileges to bypass the XSS filter by injecting unquoted HTML event attributes. This enables the execution of arbitrary JavaScript code within the context of other users who view the compromised content. The vulnerability was addressed in Grav core commit `5a12f9be8` and will be included in version 2.0.0-beta.2. This poses a significant risk to Grav CMS installations that allow untrusted users to publish content.

## Attack Chain

1. An attacker gains publisher-level access to the Grav CMS instance.
2. The attacker crafts a malicious payload containing an unquoted HTML event attribute, such as `<img src=x onerror=alert(document.cookie)>`.
3. The attacker injects the payload into a vulnerable content field, such as a blog post or page content.
4. The Grav CMS instance stores the malicious payload in its database without proper sanitization due to the flawed `detectXss()` function.
5. A user visits the page containing the injected payload.
6. The user's browser renders the HTML, including the malicious `onerror` attribute.
7. The JavaScript code within the `onerror` attribute executes, performing actions such as stealing cookies or redirecting the user to a malicious website.
8. The attacker gains unauthorized access to the user's session or performs other malicious actions.

## Impact

The successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the browser of any user who views the compromised content. This can lead to session hijacking, where the attacker steals the user's cookies and impersonates them. Attackers could also perform unauthorized actions on behalf of the user, such as modifying content, changing passwords, or accessing sensitive information. Given the high severity and ease of exploitation, all Grav CMS installations prior to version 2.0.0-beta.2 are at risk.

## Recommendation

- Upgrade to Grav CMS version 2.0.0-beta.2 or later to incorporate the fix for CVE-2026-42612.
- Deploy the Sigma rule `Detect Grav CMS XSS via Unquoted Event Attributes` to identify potential exploitation attempts.
- Review and sanitize existing content for potentially malicious unquoted HTML event attributes.
- Implement a robust HTML sanitization library to replace the blacklist-based `detectXss()` function.
