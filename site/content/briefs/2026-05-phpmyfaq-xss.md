---
title: phpMyFAQ Stored XSS Vulnerability via Malformed URLs (CVE-2026-46367)
slug: 2026-05-phpmyfaq-xss
description: phpMyFAQ before 4.1.2 contains a stored cross-site scripting vulnerability in Utils::parseUrl() that allows authenticated users to inject JavaScript via malformed URLs in comments, potentially leading to session hijacking and application takeover.
date: "2026-05-15T19:20:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - stored-xss
  - xss
  - phpmyfaq
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ < 4.1.2
cves:
  - id: CVE-2026-46367
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-46367
  - https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-9525-27vj-c8r8
  - https://www.vulncheck.com/advisories/phpmyfaq-stored-xss-via-utils-parseurl-in-comment-rendering
rules:
  - title: Detect phpMyFAQ XSS in FAQ Comments
    description: Detects CVE-2026-46367 exploitation — attempts to inject JavaScript code via malformed URLs in phpMyFAQ comments.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
  - title: Detect phpMyFAQ XSS in FAQ Comments (unescaped quotes)
    description: Detects CVE-2026-46367 exploitation — attempts to inject JavaScript code via malformed URLs in phpMyFAQ comments using unescaped quotes.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

phpMyFAQ before version 4.1.2 is vulnerable to stored cross-site scripting (XSS) in the `Utils::parseUrl()` function. The vulnerability, identified as CVE-2026-46367, allows authenticated users to inject arbitrary JavaScript code into comments by crafting malformed URLs containing unescaped quotes. When other users, including administrators, view the FAQ pages containing the malicious comments, the injected JavaScript executes in their browsers. This can lead to the theft of sensitive information like admin session cookies, ultimately enabling full application takeover. The vulnerability was reported by VulnCheck and affects deployments where user comments are enabled and not properly sanitized.

## Attack Chain

1.  Attacker authenticates to the phpMyFAQ application with a valid user account.
2.  Attacker crafts a malicious URL containing unescaped quotes and JavaScript code (e.g., `<a href="javascript:alert('XSS')">Click Here</a>`).
3.  Attacker submits a comment containing the crafted malicious URL to a FAQ page.
4.  The phpMyFAQ application stores the comment, including the malicious URL, in the database without proper sanitization or escaping.
5.  A victim user (including an administrator) views the FAQ page containing the attacker's comment.
6.  The phpMyFAQ application renders the FAQ page, embedding the malicious URL within the HTML.
7.  The victim's web browser parses the HTML and executes the injected JavaScript code from the malicious URL.
8.  The attacker's JavaScript code steals the victim's session cookies and sends them to an attacker-controlled server, allowing session hijacking.

## Impact

Successful exploitation of this stored XSS vulnerability (CVE-2026-46367) can lead to the theft of administrator session cookies, resulting in a complete takeover of the phpMyFAQ application. An attacker could then modify FAQs, inject further malicious code, or compromise sensitive data stored within the application. The severity is rated as HIGH with a CVSS v3.1 score of 7.6. The number of victims depends on the number of users who view the FAQ pages containing the injected malicious URLs.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.2 or later to patch the CVE-2026-46367 vulnerability.
*   Implement proper input validation and sanitization in the `Utils::parseUrl()` function to prevent the injection of malicious JavaScript code, specifically escaping single and double quotes.
*   Deploy the Sigma rule `Detect phpMyFAQ XSS in FAQ Comments` to identify potential exploitation attempts.
*   Regularly review user-submitted content (comments, URLs) for suspicious patterns or malicious code.
