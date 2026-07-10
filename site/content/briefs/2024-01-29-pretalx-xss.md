---
title: pretalx Stored Cross-Site Scripting Vulnerability in Organizer Search
slug: 2024-01-29-pretalx-xss
description: A stored cross-site scripting (XSS) vulnerability exists in the pretalx backend organizer search, allowing attackers to inject malicious JavaScript into user-controlled fields that executes in an organizer's browser, potentially leading to data modification or exfiltration.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - pretalx
  - xss
  - stored-xss
vendors:
  - pretalx
products:
  - pretalx
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-cjcx-jfp2-f7m2
rules:
  - title: Detect pretalx XSS Payload in HTTP URI
    description: Detects potential attempts to exploit the pretalx XSS vulnerability by searching for common XSS payloads in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect pretalx XSS Payload in HTTP Request Body
    description: Detects potential attempts to exploit the pretalx XSS vulnerability by searching for common XSS payloads in HTTP request bodies, potentially used to inject malicious content into user profiles or submission details.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stored cross-site scripting (XSS) vulnerability was discovered in the pretalx event management platform, specifically affecting versions prior to v2026.1.0. The vulnerability resides within the organizer search functionality in the backend. Attackers can inject malicious HTML or JavaScript code into user-controlled fields such as submission titles, speaker display names, or user names/emails. When an organizer performs a typeahead search that matches the injected payload, the malicious script executes within the organizer's browser session. This vulnerability allows attackers to potentially steal CSRF tokens, perform actions on behalf of the organizer, modify data, or exfiltrate sensitive information. The vulnerability was reported by Elad Meged from Novee Security and patched in pretalx v2026.1.0.

## Attack Chain

1. An attacker registers an account on the pretalx platform or utilizes an existing account.
2. The attacker modifies their display name or submission title to include a malicious JavaScript payload, such as `<script>alert("XSS")</script>`.
3. The attacker submits a proposal or registers for an event, ensuring their malicious display name is associated with their profile.
4. An organizer logs into the pretalx backend and uses the organizer search bar to search for a user or submission.
5. The organizer's search query matches the malicious record (e.g., the attacker's display name or submission title).
6. The pretalx application renders the search results using `innerHTML`, injecting the attacker's malicious JavaScript payload into the page.
7. The injected JavaScript executes within the organizer's browser session, allowing the attacker to steal the CSRF token.
8. The attacker uses the stolen CSRF token to submit authenticated requests, potentially modifying event data, exfiltrating sensitive information, or performing other actions on behalf of the organizer.

## Impact

Successful exploitation of this XSS vulnerability allows attackers to execute arbitrary JavaScript code within the browser of a pretalx organizer. This could lead to the compromise of sensitive event data, unauthorized modification of event settings, or the exfiltration of organizer credentials. The impact depends on the permissions and access levels of the compromised organizer account. If an administrator account is compromised, the attacker could gain full control over the pretalx instance, potentially affecting numerous events and users.

## Recommendation

*   Upgrade pretalx to version 2026.1.0 or later to patch the vulnerability.
*   If an immediate upgrade is not possible, avoid using the organiser search bar or apply the patch manually to `src/pretalx/static/orga/js/base.js` as described in the advisory.
*   Implement a Content Security Policy (CSP) to mitigate the risk of XSS attacks. (Not explicitly mentioned in the advisory, but a good security practice).
*   Deploy the Sigma rule below to your SIEM and tune for your environment to detect potential exploitation attempts.
