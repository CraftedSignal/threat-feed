---
title: MantisBT Vulnerable to Stored XSS in File Download
slug: 2026-05-mantisbt-xss
description: MantisBT is vulnerable to stored cross-site scripting (XSS) via file_download.php by using the `show_inline=1` parameter with a valid CSRF token to upload a crafted XHTML attachment referencing a JavaScript attachment, leading to arbitrary code execution.
date: "2026-05-11T19:42:20Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - xss
  - mantisbt
  - github advisory
vendors:
  - composer
products:
  - mantisbt/mantisbt (<= 2.28.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://github.com/advisories/GHSA-p6fr-rxq7-xcg8
  - CVE-2026-44657
rules:
  - title: Detect MantisBT XSS via file_download.php
    description: Detects CVE-2026-44657 exploitation - Suspicious access to file_download.php with show_inline parameter, potentially indicative of XSS attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - webserver
  - title: Detect MantisBT Suspicious Attachment Uploads
    description: Detects suspicious attachment uploads to MantisBT with potential XSS vectors. This looks for XHTML files referencing JavaScript files which are common XSS attack vectors.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

MantisBT, a web-based bug tracking system, is vulnerable to a stored cross-site scripting (XSS) attack. The vulnerability exists in the `file_download.php` script. By exploiting this flaw, an attacker can inject malicious JavaScript code into the application, which will be executed in the context of other users' browsers when they access the affected functionality. The vulnerability is triggered when processing file downloads, specifically when the `show_inline=1` parameter is used in conjunction with a valid `file_show_inline_token` CSRF token. This allows an attacker to upload a crafted XHTML attachment that references a JavaScript attachment. The vulnerability affects MantisBT versions 2.28.1 and earlier. This can lead to account takeover, sensitive data leakage, and other malicious activities.

## Attack Chain

1.  Attacker authenticates to MantisBT as a user with permissions to upload attachments.
2.  Attacker crafts a malicious JavaScript file (e.g., `evil.js`) containing the XSS payload.
3.  Attacker crafts a malicious XHTML file (e.g., `evil.xhtml`) that includes the JavaScript file using `<script src="evil.js"></script>`.
4.  Attacker obtains a valid CSRF token for the `file_show_inline_token` parameter.
5.  Attacker uploads both the `evil.js` and `evil.xhtml` files as attachments to a MantisBT issue.
6.  Attacker crafts a request to `file_download.php` with the `show_inline=1` parameter, the valid CSRF token, and the file IDs of the uploaded `evil.xhtml` attachment.
7.  A victim user clicks a link (or is redirected) to the crafted `file_download.php` URL.
8.  The server serves the `evil.xhtml` file inline, which executes the embedded `evil.js` JavaScript in the victim's browser, allowing the attacker to perform actions on behalf of the victim.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the context of a victim's browser. This can lead to a variety of malicious activities, including session hijacking, defacement of the MantisBT interface, theft of sensitive information, or further exploitation of the MantisBT server or the victim's machine. Given the nature of bug tracking systems, successful exploitation could impact multiple users within an organization, potentially leading to widespread compromise.

## Recommendation

*   Apply the patch provided by MantisBT (26647b2e68ba30b9d7987d4e03d7a16416684bc2) to remediate the vulnerability.
*   Deploy the Sigma rule "Detect MantisBT XSS via file_download.php" to identify potential exploitation attempts.
*   Monitor web server logs for requests to `file_download.php` with the `show_inline=1` parameter and potentially malicious content in the request.
