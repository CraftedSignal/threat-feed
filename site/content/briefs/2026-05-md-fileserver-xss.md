---
title: md-fileserver Stored/Reflected XSS Vulnerability
slug: 2026-05-md-fileserver-xss
description: A cross-site scripting (XSS) vulnerability exists in md-fileserver's Markdown rendering logic, where user-supplied Markdown content containing raw HTML, including <script> tags, is processed and injected into the resulting page without sanitization, leading to arbitrary JavaScript execution and potential account takeover.
date: "2026-05-21T17:59:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xss
  - reflected-xss
  - stored-xss
  - javascript
  - md-fileserver
vendors:
  - npm
products:
  - md-fileserver (< 1.10.3)
references:
  - https://github.com/advisories/GHSA-32q2-hhr5-6qvv
  - CVE-2026-46492
iocs:
  - type: url
    value: https://79evxsw3m08qfyvxluebgl0pyg47szgo.oastify.com/exfil
ioc_counts:
  url: 1
rules:
  - title: Detect md-fileserver XSS via oastify.com
    description: Detects XSS exploitation attempts in md-fileserver by monitoring network connections to the exfiltration domain oastify.com.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - windows
  - title: Detect md-fileserver XSS via script tag in request
    description: Detects XSS exploitation attempts in md-fileserver by monitoring web server logs for requests containing script tags.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
rules_count: 2
---

md-fileserver versions prior to 1.10.3 are vulnerable to cross-site scripting (XSS) due to the application's Markdown rendering configuration which allows raw HTML. An attacker can inject malicious JavaScript code into Markdown files. When a user views the crafted Markdown, the injected script executes in the user's browser. This vulnerability arises from the application's explicit configuration to allow raw HTML within Markdown and the subsequent lack of sanitization before rendering the content in the HTML template. This can lead to session hijacking, credential theft, or other malicious activities. The vulnerability was reported on May 21, 2026.

## Attack Chain

1.  The attacker crafts a malicious Markdown file containing an embedded `<script>` tag or event handler (e.g., `<img onerror=...>`).
2.  The attacker hosts or uploads this malicious Markdown file to the md-fileserver application.
3.  A victim user navigates to the malicious Markdown file hosted on the md-fileserver.
4.  The application's `lib/markd.js` renders the Markdown content without sanitizing the raw HTML, including the malicious `<script>` tag.
5.  The rendered Markdown is injected into the HTML template `lib/pages/template.html` using `<%= markdown %>` without any sanitization or output encoding.
6.  The victim's browser receives the HTML page with the embedded malicious JavaScript code.
7.  The JavaScript code executes in the victim's browser within the security context of the md-fileserver domain.
8.  The attacker achieves their objective, such as stealing session cookies, redirecting the user to a phishing site, or defacing the website.

## Impact

Successful exploitation allows an attacker to execute arbitrary JavaScript in the victim’s browser. This can lead to session hijacking, account takeover, credential theft, defacement of the website, or exfiltration of sensitive data such as API tokens, CSRF tokens, or user information. All users who view Markdown content within the vulnerable application are potentially affected. Versions of `md-fileserver` prior to `1.10.3` are vulnerable.

## Recommendation

*   Upgrade `md-fileserver` to version 1.10.3 or later to remediate the XSS vulnerability.
*   Deploy the Sigma rule `Detect md-fileserver XSS via oastify.com` to detect potential exploitation attempts by monitoring network connections to the exfiltration domain.
*   Implement proper HTML sanitization and output encoding in `lib/markd.js` to prevent the execution of arbitrary JavaScript code.
*   Disable the `html: true` option in the MarkdownIt configuration (config.js) if raw HTML rendering is not required.
