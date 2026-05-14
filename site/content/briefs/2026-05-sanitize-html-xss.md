---
title: sanitize-html XSS Vulnerability via XMP Tag Bypass (CVE-2026-44990)
slug: 2026-05-sanitize-html-xss
description: sanitize-html version 2.17.3 and earlier is vulnerable to cross-site scripting (XSS) due to the improper handling of the `xmp` tag, allowing attackers to inject arbitrary HTML and JavaScript code.
date: "2026-05-14T18:27:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - xss
  - sanitize-html
  - javascript
  - sanitization
vendors:
  - npm
products:
  - sanitize-html (<= 2.17.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-rpr9-rxv7-x643
  - CVE-2026-44990
rules:
  - title: Detect sanitize-html XSS via XMP Tag Bypass
    description: Detects CVE-2026-44990 exploitation -- attempts to inject JavaScript code through the `xmp` tag using `sanitize-html` library.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
  - title: Detect sanitize-html XSS via XMP Tag img Bypass
    description: Detects CVE-2026-44990 exploitation -- attempts to inject JavaScript code via onerror event in img tag within xmp using `sanitize-html` library.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `sanitize-html` library, a widely used HTML sanitizer for Node.js, contains a critical cross-site scripting (XSS) vulnerability (CVE-2026-44990) affecting version 2.17.3 and earlier. The vulnerability arises from the omission of the `xmp` tag from the default `nonTextTags` list in the library's configuration. This oversight, combined with the special handling of `xmp` content in the `ontext` handler, allows attacker-controlled content within a disallowed `xmp` element to be rendered as live HTML or JavaScript. The issue was identified and disclosed on May 14, 2026. Exploitation can lead to arbitrary JavaScript execution in a user's browser, impacting applications that rely on `sanitize-html` for input sanitization.

## Attack Chain

1.  The attacker crafts malicious HTML containing JavaScript code wrapped within an `<xmp>` tag (e.g., `<xmp><script>alert(1)</script></xmp>`).
2.  The application utilizes `sanitize-html` version 2.17.3 or earlier with default settings to sanitize the malicious HTML.
3.  Due to the omission of `xmp` from the `nonTextTags` list, `sanitize-html` does not treat the `xmp` tag as a container to be completely discarded.
4.  The `ontext` handler in `sanitize-html` appends the content within the `xmp` tag directly to the output without proper escaping.
5.  The sanitized output, still containing the unescaped JavaScript code from within the `<xmp>` tag, is stored in the application's database or displayed to other users.
6.  When a user views the stored or displayed content, the browser renders the unescaped JavaScript code within the now-live HTML structure.
7.  The attacker's JavaScript code executes in the user's browser, potentially stealing sensitive information, performing actions on behalf of the user, or defacing the application.

## Impact

This XSS vulnerability allows a remote attacker to inject arbitrary JavaScript into a user's browser. Successful exploitation can lead to session hijacking, sensitive data theft, account takeover, and defacement of the application. Applications that rely on `sanitize-html` for input sanitization and render the output as trusted HTML are vulnerable. The severity is rated as critical due to the ease of exploitation and potential impact.

## Recommendation

*   Upgrade to `sanitize-html` version 2.18.0 or later, where this vulnerability is resolved.
*   As a temporary workaround, configure `sanitize-html` to explicitly disallow the `xmp` tag or to escape its content.
*   Deploy the Sigma rule `Detect sanitize-html XSS via XMP Tag Bypass` to identify exploitation attempts (process_creation).
*   Review and update any existing sanitization configurations to ensure that potentially dangerous tags are properly handled.
