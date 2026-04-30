---
title: Case Theme User WordPress Plugin Local File Inclusion Vulnerability (CVE-2025-5804)
slug: 2026-04-case-theme-lfi
description: CVE-2025-5804 is a PHP Local File Inclusion vulnerability in the Case Theme User WordPress plugin before version 1.0.4 due to improper filename control in include/require statements, potentially allowing attackers to execute arbitrary code by including malicious local files.
date: "2026-04-11T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - php
  - lfi
  - wordpress
  - cve-2025-5804
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-5804
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-5804
  - https://patchstack.com/database/wordpress/plugin/case-theme-user/vulnerability/wordpress-case-theme-user-1-0-4-local-file-inclusion-vulnerability?_s_id=cve
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Case Theme User LFI Attempt
    description: Detects potential Local File Inclusion (LFI) attempts targeting the Case Theme User WordPress plugin by monitoring HTTP requests containing directory traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect PHP file access outside webroot
    description: Detects potential Local File Inclusion (LFI) attempts by monitoring PHP file access outside the webroot.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A local file inclusion (LFI) vulnerability, identified as CVE-2025-5804, affects the Case Theme User WordPress plugin before version 1.0.4. The vulnerability stems from insufficient validation of filenames passed to PHP's `include` or `require` statements. This allows an unauthenticated attacker to potentially include arbitrary local files on the server hosting the WordPress instance. Successful exploitation could lead to sensitive information disclosure, arbitrary code execution, or denial of service. The vulnerability was reported and patched by Patchstack. Users of the Case Theme User plugin are advised to upgrade to version 1.0.4 or later to mitigate this risk.

## Attack Chain

1.  An attacker identifies a vulnerable Case Theme User plugin running on a WordPress site.
2.  The attacker crafts a malicious HTTP request targeting a PHP file within the plugin that uses an `include` or `require` statement.
3.  The attacker modifies a GET or POST parameter associated with the vulnerable `include` or `require` statement, injecting a path to a local file (e.g., `/etc/passwd`).
4.  The web server processes the request, and the PHP interpreter attempts to include the file specified in the attacker-controlled parameter.
5.  Due to the LFI vulnerability, the server includes the attacker-specified local file.
6.  If the included file contains sensitive data, such as configuration files or credentials, the attacker can extract this information from the server's response.
7.  In more advanced scenarios, the attacker might attempt to include PHP files containing malicious code, achieving remote code execution on the server.

## Impact

Successful exploitation of CVE-2025-5804 can lead to a range of impacts, including sensitive information disclosure such as WordPress configuration files (wp-config.php), which contain database credentials. Arbitrary code execution is possible if the attacker can include a file containing malicious PHP code. This could allow the attacker to gain complete control of the WordPress site and the underlying server. The number of affected sites depends on the adoption rate of the vulnerable Case Theme User plugin, but given the widespread use of WordPress, the potential impact could be significant.

## Recommendation

*   Immediately update the Case Theme User WordPress plugin to version 1.0.4 or later to patch CVE-2025-5804.
*   Deploy the Sigma rule `Detect Case Theme User LFI Attempt` to your SIEM to identify potential exploitation attempts based on suspicious file paths in HTTP requests.
*   Monitor web server logs for unusual file access patterns, particularly requests containing "..", "%2e%2e", or other directory traversal sequences, to catch LFI attempts (see log source `webserver`).
