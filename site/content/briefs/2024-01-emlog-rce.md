---
title: Emlog Path Traversal Vulnerability Leads to Remote Code Execution
slug: 2024-01-emlog-rce
description: Emlog versions 2.6.2 and prior are vulnerable to path traversal via crafted ZIP uploads, allowing authenticated admins to write arbitrary files and achieve remote code execution.
date: "2026-04-03T23:17:04Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - path-traversal
  - remote-code-execution
  - emlog
  - web-application
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-34607
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34607
rules:
  - title: Detect Web Request for Potentially Uploaded Webshell
    description: Detects requests to PHP files outside the webroot, indicating potential webshell uploads after exploiting CVE-2026-34607.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect Webshell Execution from Web Server Process
    description: Detects process creation events originating from web server processes, indicating potential webshell execution after exploiting CVE-2026-34607.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Emlog, an open-source website building system, is vulnerable to a critical path traversal vulnerability (CVE-2026-34607) affecting versions 2.6.2 and earlier. This flaw resides within the `emUnZip()` function located in `include/lib/common.php:793`. The vulnerability stems from the function's failure to sanitize ZIP entry names during extraction of ZIP archives, such as those used for plugin/template uploads or backup imports. An authenticated administrator can exploit this by uploading a specially crafted ZIP file containing entries with "../" sequences. This allows the attacker to write arbitrary files to the server's file system, potentially including PHP webshells, ultimately leading to Remote Code Execution (RCE). At the time of this writing, there are no publicly available patches to address this vulnerability.

## Attack Chain

1. The attacker authenticates as an administrator in the Emlog application.
2. The attacker crafts a malicious ZIP archive containing a file with a path traversal sequence (e.g., `../../../../shell.php`).
3. The attacker uploads the crafted ZIP archive via a plugin/template upload or backup import feature.
4. The `emUnZip()` function is invoked, which extracts the contents of the ZIP archive.
5. Due to the lack of sanitization, the `extractTo()` function writes the malicious file to an arbitrary location on the server's filesystem, as dictated by the path traversal sequence.
6. The attacker uploads a PHP webshell to a publicly accessible directory.
7. The attacker accesses the uploaded PHP webshell through a web browser (e.g., `http://example.com/shell.php`).
8. The attacker executes arbitrary commands on the server via the webshell, achieving Remote Code Execution (RCE).

## Impact

Successful exploitation of this vulnerability allows an attacker to gain complete control over the affected Emlog server. This can lead to data breaches, website defacement, malware distribution, or further attacks against other systems on the network. Given that Emlog is used by numerous websites, the potential impact could be widespread, affecting potentially hundreds or thousands of websites.

## Recommendation

*   Apply any available patches or updates for Emlog as soon as they are released to address CVE-2026-34607.
*   Implement input validation and sanitization measures within the `emUnZip()` function to prevent path traversal attacks. Specifically, sanitize ZIP entry names before passing them to the `extractTo()` function.
*   Monitor web server logs for suspicious requests to PHP files in unusual directories (e.g., outside the webroot) after ZIP archive uploads, using the provided Sigma rule for webserver logs.
*   Implement the provided Sigma rule to detect process creation from web server processes to identify potential webshell execution.
