---
title: SourceCodester Leave Application System 1.0 File Inclusion Vulnerability (CVE-2026-5210)
slug: 2026-04-sourcecodester-lfi
description: SourceCodester Leave Application System 1.0 is vulnerable to remote file inclusion (CVE-2026-5210) due to improper handling of the 'page' argument, potentially allowing attackers to execute arbitrary code.
date: "2026-03-31T19:16:29Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-5210
  - file-inclusion
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5210
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5210
  - https://medium.com/@hemantrajbhati5555/local-file-inclusion-lfi-in-leave-application-system-php-sqlite3-4e095bb7ee40
  - https://vuldb.com/submit/780419
  - https://vuldb.com/vuln/354346
  - https://vuldb.com/vuln/354346/cti
  - https://www.sourcecodester.com/
iocs:
  - type: url
    value: https://medium.com/@hemantrajbhati5555/local-file-inclusion-lfi-in-leave-application-system-php-sqlite3-4e095bb7ee40
  - type: url
    value: https://www.sourcecodester.com/
ioc_counts:
  url: 2
rules:
  - title: Detect LFI Attempts via Page Parameter
    description: Detects attempts to exploit LFI vulnerabilities by analyzing the 'page' parameter in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect access to sensitive files via web server
    description: Detects access to common sensitive files via web requests that may indicate LFI or other vulnerability
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SourceCodester Leave Application System version 1.0 is vulnerable to a file inclusion vulnerability (CVE-2026-5210). This vulnerability allows a remote attacker to include arbitrary files on the server by manipulating the `page` argument in a request.  The vulnerability exists because the application fails to properly sanitize user-supplied input, leading to the inclusion of potentially malicious files. Public exploits are available, increasing the risk of exploitation. This vulnerability poses a significant threat to organizations using the affected application, as it can lead to remote code execution and data exfiltration.

## Attack Chain

1. The attacker identifies a page within the SourceCodester Leave Application System 1.0 that uses the `page` parameter to include files.
2. The attacker crafts a malicious URL containing the `page` parameter, injecting a path to a local file (e.g., `../../../../etc/passwd`) or a remote file via a URL.
3. The vulnerable application processes the attacker-supplied `page` parameter without proper sanitization or validation.
4. The application attempts to include the file specified by the attacker's malicious URL.
5. If the file is successfully included, the attacker can read sensitive information (e.g., `/etc/passwd`, database configuration files).
6. If the attacker can include a PHP file (e.g., via a log poisoning attack), they can achieve remote code execution on the server.
7. The attacker executes arbitrary commands on the server with the privileges of the web server user.
8. The attacker can then pivot to other systems, install malware, or exfiltrate sensitive data.

## Impact

Successful exploitation of this vulnerability can lead to unauthorized access to sensitive information, such as configuration files, source code, and user credentials.  Remote code execution is possible if the attacker can include a PHP file, potentially leading to complete system compromise.  This could impact all users of the Leave Application System, potentially exposing employee data.

## Recommendation

*   Apply available patches or upgrade to a secure version of SourceCodester Leave Application System to remediate CVE-2026-5210.
*   Deploy the provided Sigma rule to detect attempts to exploit the file inclusion vulnerability by monitoring for suspicious `page` parameter values in web server logs.
*   Implement strict input validation and sanitization for all user-supplied input, especially parameters used for file inclusion.
*   Restrict file system access for the web server user to only the necessary directories to prevent unauthorized file access.
*   Monitor web server logs for access to sensitive files, such as `/etc/passwd`, database configuration files, and application source code.
*   Block the reported malicious URL `https://medium.com/@hemantrajbhati5555/local-file-inclusion-lfi-in-leave-application-system-php-sqlite3-4e095bb7ee40` at the network perimeter.
