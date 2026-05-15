---
title: NukeViet CMS Stored XSS Vulnerability via Insufficient Input Sanitization (CVE-2026-41147)
slug: 2026-05-nukeviet-xss
description: NukeViet CMS version 4.5.08 and earlier is vulnerable to stored cross-site scripting (XSS) via insufficient server-side input sanitization in the Request class, allowing attackers to inject malicious payloads that can lead to session hijacking, defacement, and phishing attacks.
date: "2026-05-15T16:47:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - stored-xss
  - nukeviet
  - cve-2026-41147
vendors:
  - NukeViet
products:
  - NukeViet CMS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-64rr-pp78-62ww
  - https://cwe.mitre.org/data/definitions/79.html
  - https://github.com/nukeviet/nukeviet/blob/nukeviet4.5/modules/contact/funcs/main.php
rules:
  - title: Detect NukeViet XSS Payload
    description: Detects potential XSS payloads being submitted to NukeViet CMS via HTTP POST requests, indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect NukeViet XSS - HTML Event Attributes
    description: Detects potential XSS exploitation attempts targeting NukeViet by searching for HTML event attributes in web server logs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

NukeViet CMS version 4.5.08 and earlier contains a stored cross-site scripting (XSS) vulnerability (CVE-2026-41147) due to insufficient server-side input sanitization within the Request class. The application's reliance on client-side filtering for HTML input allows attackers to bypass security measures by directly modifying HTTP requests, for example using tools like Burp Suite. This vulnerability impacts modules accepting user-submitted HTML through the Request class, allowing attackers to inject malicious payloads that are stored server-side and subsequently executed in the browsers of users viewing the compromised content. The Contact module was identified as a proof-of-concept, though other modules are also susceptible. No authentication is required to exploit the vulnerability.

## Attack Chain

1.  An attacker identifies a NukeViet CMS instance running a vulnerable version (<= 4.5.08).
2.  The attacker locates an input field (e.g., in the Contact module) that utilizes the Request class for processing HTML content.
3.  The attacker crafts a malicious XSS payload, such as `<iframe srcdoc="&lt;img src=1 onerror=alert(document.cookie)&gt;"></iframe>`, designed to execute JavaScript code in the victim's browser.
4.  The attacker intercepts the HTTP request containing the form submission (e.g., using Burp Suite) and modifies the request to inject the crafted XSS payload into the vulnerable input field.
5.  The server stores the attacker's payload in the database.
6.  A user (e.g., an administrator or moderator) views the content containing the stored XSS payload.
7.  The user's browser executes the malicious JavaScript code embedded in the iframe.
8.  The attacker gains unauthorized access to the user's session cookies, performs actions under the victim's identity, defaces the website, redirects the user to a phishing page, or performs phishing attacks.

## Impact

Successful exploitation of this vulnerability can lead to various adverse outcomes. Administrators and moderators are at risk when viewing user-submitted content containing malicious payloads. The vulnerability can result in session hijacking via cookie theft, unauthorized actions performed under the victim's identity, defacement of the website, redirection to phishing pages, and phishing attacks via manipulated email notifications. This vulnerability allows unauthenticated attackers to inject arbitrary JavaScript code into the application, affecting all users who interact with the stored payload.

## Recommendation

*   Upgrade to NukeViet version 4.5.08 or later to patch CVE-2026-41147 as recommended by the vendor.
*   Deploy the Sigma rule "Detect NukeViet XSS Payload" to identify potential exploitation attempts targeting the Request class via HTTP POST requests.
*   Implement server-side HTML sanitization in the Request class to strip or encode potentially harmful tags and attributes as a general security measure.
