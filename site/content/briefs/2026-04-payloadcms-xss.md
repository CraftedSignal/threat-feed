---
title: Payload CMS Stored XSS Vulnerability (CVE-2026-34748)
slug: 2026-04-payloadcms-xss
description: A stored Cross-Site Scripting (XSS) vulnerability exists in Payload CMS versions prior to 3.78.0, allowing authenticated users with write access to inject malicious scripts that execute in the browsers of other users.
date: "2026-04-01T20:16:27Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - xss
  - cve-2026-34748
  - payloadcms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34748
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34748
  - https://github.com/payloadcms/payload/security/advisories/GHSA-mmxc-95ch-2j7c
rules:
  - title: Detect Script Tag Injection in HTTP Request Parameters
    description: Detects potential XSS attacks by identifying script tags within HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Script Tag Injection in HTTP Request Body
    description: Detects potential XSS attacks by identifying script tags within HTTP request body.
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

Payload CMS is a free and open-source headless content management system. Prior to version 3.78.0, a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-34748) existed in the admin panel of @payloadcms/next. This vulnerability allows an authenticated user with write access to a collection to save malicious content, which, when viewed by another user, results in arbitrary JavaScript execution within their browser. Successful exploitation can lead to session hijacking, defacement, or other malicious actions performed on behalf of the victim user. The vulnerability was patched in version 3.78.0. This issue poses a risk to any organization using Payload CMS, particularly those where multiple users with differing levels of trust interact with the content management system.

## Attack Chain

1.  Attacker authenticates to the Payload CMS admin panel with write access to a collection.
2.  Attacker crafts malicious content containing a JavaScript payload, such as `<script>alert("XSS")</script>`.
3.  The attacker saves the malicious content within a collection in the CMS through the admin panel interface, likely using a text field or similar input.
4.  The CMS stores the malicious content in its database without proper sanitization or output encoding.
5.  A different, authenticated user accesses the collection containing the attacker's malicious content through the admin panel using their web browser.
6.  The CMS retrieves the malicious content from the database and renders it in the victim user's browser.
7.  The victim's browser executes the injected JavaScript code within the context of the Payload CMS web application.
8.  The attacker achieves XSS, potentially gaining access to the victim's session cookies, defacing the admin panel, or redirecting the user to a phishing site.

## Impact

Successful exploitation of this stored XSS vulnerability (CVE-2026-34748) in Payload CMS can lead to several negative consequences. An attacker can hijack the session of an administrator, potentially gaining full control over the CMS and its managed content. The attacker can also deface the admin panel, inject malicious links, or redirect users to phishing sites. Given the nature of content management systems, a successful XSS attack could lead to widespread distribution of malicious content to website visitors, ultimately harming the organization's reputation and potentially leading to data breaches.

## Recommendation

*   Upgrade Payload CMS to version 3.78.0 or later to patch CVE-2026-34748, as indicated in the overview.
*   Implement a Content Security Policy (CSP) to restrict the sources from which the browser is permitted to load resources to mitigate potential XSS exploitation.
*   Deploy the provided Sigma rule targeting script tag injection within HTTP request parameters to detect potential exploitation attempts against web applications.
*   Monitor web server logs for unusual activity related to the Payload CMS admin panel, focusing on requests containing potentially malicious JavaScript code.
