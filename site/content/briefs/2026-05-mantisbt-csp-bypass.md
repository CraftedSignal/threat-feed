---
title: MantisBT Content Security Policy Bypass via Attachment Upload (CVE-2026-40597)
slug: 2026-05-mantisbt-csp-bypass
description: A content security policy bypass vulnerability, CVE-2026-40597, exists in MantisBT versions 2.28.1 and earlier, allowing an attacker to bypass the _script-src_ directive by uploading a crafted attachment that, when downloaded, executes as JavaScript due to MIME type sniffing, given a pre-existing XSS / HTML injection vulnerability.
date: "2026-05-11T19:35:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - csp-bypass
  - xss
  - attachment
  - mime-sniffing
vendors:
  - MantisBT
products:
  - mantisbt (<= 2.28.1)
  - mantisbt/mantisbt
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-9c3j-xm6v-j7j3
  - CVE-2026-40597
rules:
  - title: Detect MantisBT CSP Bypass via JavaScript MIME Sniffing
    description: Detects CVE-2026-40597 exploitation — crafted attachment upload in MantisBT leading to CSP bypass due to JavaScript MIME sniffing.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - webserver
  - title: Detect MantisBT Attachment Upload with Suspicious File Extensions
    description: Detects suspicious file extensions being uploaded as attachments to MantisBT issues, which may indicate an attempt to exploit vulnerabilities like CVE-2026-40597.
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

MantisBT, a web-based bug tracking system, is vulnerable to a content security policy (CSP) bypass. Specifically, the vulnerability, identified as CVE-2026-40597, allows an attacker to circumvent the CSP's `script-src` directive. This is achieved by uploading a specially crafted attachment to a MantisBT issue. The vulnerability exists in MantisBT versions 2.28.1 and earlier. An attacker must first inject HTML or XSS. When the attachment is accessed via the `file_download.php` link, PHP's finfo mechanism incorrectly identifies it as a valid JavaScript MIME type. Because of this, the browser executes the payload within the context of the MantisBT application. This can lead to Cross-Site Scripting (XSS) attacks.

## Attack Chain

1.  Attacker identifies or exploits an existing XSS or HTML injection vulnerability in MantisBT.
2.  Attacker crafts a malicious payload designed to execute JavaScript code within the browser, and ensures that it will be sniffed as JavaScript by PHP's `finfo`.
3.  Attacker uploads the crafted payload as an attachment to a MantisBT issue using the standard attachment upload functionality.
4.  MantisBT stores the attachment, associating it with the specific issue.
5.  A user (victim) accesses the issue containing the malicious attachment.
6.  The user clicks the `file_download.php` link associated with the uploaded attachment.
7.  The webserver serves the attachment via `file_download.php`. PHP's `finfo` incorrectly identifies the MIME type of the file as a valid JavaScript MIME type.
8.  The browser imports the attachment as a `<script>` tag and executes the attacker-controlled JavaScript code within the security context of the MantisBT domain, leading to XSS.

## Impact

Successful exploitation of this vulnerability, in conjunction with a pre-existing XSS or HTML injection, allows an attacker to execute arbitrary JavaScript code in the context of the MantisBT application. This can lead to session hijacking, defacement of the MantisBT interface, sensitive information theft, or other malicious actions performed on behalf of the victim user. Given the wide use of MantisBT in software development and IT support organizations, a successful attack could impact a significant number of users.

## Recommendation

*   Upgrade MantisBT to a patched version beyond 2.28.1 as indicated in the advisory (https://github.com/advisories/GHSA-9c3j-xm6v-j7j3).
*   Deploy the Sigma rule `Detect MantisBT CSP Bypass via JavaScript MIME Sniffing` to detect attempts to exploit CVE-2026-40597.
*   Review and harden input validation and output encoding mechanisms to prevent XSS vulnerabilities, which are a prerequisite for exploiting CVE-2026-40597.
