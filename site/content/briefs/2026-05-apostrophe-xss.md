---
title: ApostropheCMS Stored XSS via Image Widget Link (CVE-2026-45011)
slug: 2026-05-apostrophe-xss
description: 'A stored cross-site scripting vulnerability (CVE-2026-45011) was identified in ApostropheCMS image widget functionality, where a user with the Editor role can configure an image widget link to use a javascript: URL payload, which will execute arbitrary JavaScript in the victim’s browser when clicked.'
date: "2026-05-14T18:30:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - apostrophecms
  - cve-2026-45011
  - javascript
vendors:
  - Apostrophe
products:
  - apostrophecms (= 4.29.0)
references:
  - https://github.com/advisories/GHSA-5f64-7vfc-rcx6
  - CVE-2026-45011
rules:
  - title: Detect ApostropheCMS XSS via Javascript URL
    description: 'Detects XSS attempts in ApostropheCMS by identifying javascript: URLs used in image widget links (CVE-2026-45011)'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
  - title: Detect Script Tag Injection in ApostropheCMS Widget Configuration
    description: Detects attempts to inject script tags into ApostropheCMS widget configurations, potentially leading to XSS (CVE-2026-45011).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

A stored cross-site scripting (XSS) vulnerability exists within the image widget functionality of ApostropheCMS version 4.29.0. An attacker with Editor privileges can inject malicious JavaScript code by configuring an image widget's link field with a `javascript:` URL. This vulnerability allows the attacker to execute arbitrary JavaScript code in the browsers of other users who interact with the compromised image link, including administrators and public visitors. The vulnerability is identified as CVE-2026-45011.

## Attack Chain

1. An attacker logs into ApostropheCMS with Editor privileges.
2. The attacker navigates to the home page and enables edit mode.
3. The attacker adds an Image widget to the main content area.
4. The attacker selects an existing image from the media library.
5. The attacker opens the image widget settings.
6. In the "Link to" field, the attacker selects the "URL" option.
7. In the URL field, the attacker enters a malicious `javascript:` payload (e.g., `javascript:alert(document.domain)`).
8. The attacker saves the widget and updates the page, publishing the malicious content.
9. A victim (administrator or guest) visits the published page and clicks on the linked image.
10. The JavaScript payload executes in the victim's browser, potentially allowing the attacker to perform actions on their behalf.

## Impact

Successful exploitation allows an attacker with Editor privileges to store a malicious JavaScript payload in a published page within ApostropheCMS. When other users, including administrators or public visitors, click on the affected image link, the injected JavaScript executes in their browsers. This can lead to account compromise, access to sensitive data, modification of content, phishing attacks, and overall compromise of visitors who interact with the malicious image link.

## Recommendation

Prioritize the following actions to mitigate this XSS vulnerability:

*   Implement the vendor's recommended URL validation and sanitization for widget link fields to reject dangerous schemes like `javascript:` and `data:`.
*   Deploy the Sigma rule `Detect ApostropheCMS XSS via Javascript URL` to identify potential exploitation attempts.
*   Consider implementing a strict Content Security Policy (CSP) to limit the impact of potential XSS vulnerabilities.
*   Upgrade ApostropheCMS to a version that addresses CVE-2026-45011.
