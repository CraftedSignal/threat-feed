---
title: Ory Polis DOM-based XSS Vulnerability (CVE-2026-33506)
slug: 2024-01-ory-polis-xss
description: Ory Polis versions prior to 26.2.0 are vulnerable to DOM-based XSS due to improper handling of the `callbackUrl` parameter, allowing attackers to execute arbitrary JavaScript in a user's browser.
date: "2026-03-26T19:17:05Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - xss
  - ory-polis
  - cve-2026-33506
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33506
rules:
  - title: Detect Suspicious CallbackUrl Parameter
    description: Detects suspicious requests containing potentially malicious JavaScript code in the callbackUrl parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious CallbackUrl with Obfuscated JavaScript
    description: Detects potentially malicious requests with callbackUrl parameter containing obfuscated JavaScript
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

Ory Polis, formerly known as BoxyHQ Jackson, is a service that bridges or proxies SAML login flows to OAuth 2.0 or OpenID Connect. A DOM-based Cross-Site Scripting (XSS) vulnerability has been identified in versions of Ory Polis prior to 26.2.0. This vulnerability arises from the application's improper trust of the `callbackUrl` URL parameter within its login functionality. An attacker can exploit this by crafting a malicious link containing JavaScript code within the `callbackUrl`. When a…
