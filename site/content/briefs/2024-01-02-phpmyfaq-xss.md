---
title: phpMyFAQ Stored XSS Vulnerability in Comment Rendering
slug: 2024-01-02-phpmyfaq-xss
description: A stored XSS vulnerability in phpMyFAQ version 4.1.1 allows an authenticated user to inject JavaScript code into comments, leading to session cookie theft and potential admin account takeover when other users view the affected FAQ or News page.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - phpmyfaq
  - stored-xss
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ 4.1.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-9525-27vj-c8r8
iocs:
  - type: url
    value: https://www.evil.com/"onmouseover="alert(document.cookie)
ioc_counts:
  url: 1
rules:
  - title: Detect phpMyFAQ XSS Payload in Comments
    description: Detects XSS payloads in HTTP requests to phpMyFAQ comment submission endpoints.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
      - linux
  - title: Detect phpMyFAQ Admin Comment Panel Access
    description: Detects access to the phpMyFAQ admin comment panel, which can be targeted by XSS.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

phpMyFAQ version 4.1.1 is vulnerable to a stored Cross-Site Scripting (XSS) vulnerability due to improper sanitization of URLs within user comments. An attacker with a registered user account can inject malicious JavaScript code into a comment. This code is then executed when other users, including administrators, view the FAQ or news page containing the comment. The vulnerability stems from the `Utils::parseUrl()` function, which converts URLs in comments to clickable links without proper HTML escaping, allowing for the injection of arbitrary HTML attributes. This can lead to session cookie theft and full administrative account takeover.

## Attack Chain

1. An attacker registers a user account on the phpMyFAQ instance.
2. The attacker identifies a FAQ entry or News page where comments are enabled (`main.enableCommentEditor = true`).
3. The attacker crafts a malicious URL containing JavaScript code, such as `https://www.evil.com/"onmouseover="alert(document.cookie)`.
4. The attacker submits the malicious URL as part of a comment on the targeted FAQ entry or News page.
5. The `Utils::parseUrl()` function processes the comment, converting the URL into an HTML `<a>` tag without proper sanitization.
6. The crafted URL, including the injected JavaScript, is stored in the phpMyFAQ database.
7. When another user, including an administrator, views the FAQ entry or News page, the malicious JavaScript is executed in their browser.
8. The attacker steals the user's session cookie, potentially leading to account takeover, especially if the victim is an administrator.

## Impact

Successful exploitation of this stored XSS vulnerability allows an attacker to inject arbitrary JavaScript code into phpMyFAQ pages. This can lead to session cookie theft, potentially resulting in the takeover of user accounts, including administrative accounts. Given the lack of Content-Security-Policy headers, the impact is magnified. This vulnerability affects all visitors to the page with the malicious comment, and the injected code persists until the comment is manually removed.

## Recommendation

*   Upgrade to a patched version of phpMyFAQ that addresses the XSS vulnerability.
*   Apply HTML escaping to user-supplied URLs when rendering comments to prevent arbitrary HTML injection.
*   Implement a Content Security Policy (CSP) to restrict the execution of inline JavaScript.
*   Deploy the Sigma rule `Detect phpMyFAQ XSS Payload in Comments` to identify potential exploitation attempts (see below).
*   Monitor web server logs for requests containing the XSS payload `https://www.evil.com/"onmouseover="alert(document.cookie)` (see IOCs).
