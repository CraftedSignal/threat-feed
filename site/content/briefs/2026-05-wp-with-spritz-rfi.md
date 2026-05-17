---
title: WordPress WP with Spritz Plugin 1.0 Remote File Inclusion
slug: 2026-05-wp-with-spritz-rfi
description: The WordPress WP with Spritz plugin version 1.0 is vulnerable to remote file inclusion (RFI), allowing unauthenticated attackers to read arbitrary files by injecting file paths into the `url` parameter of the `wp.spritz.content.filter.php` endpoint, potentially exposing sensitive system configuration and credentials.
date: "2026-05-17T13:19:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rfi
  - wordpress
  - cve-2018-25329
  - remote-file-inclusion
vendors:
  - WordPress
products:
  - WP with Spritz plugin 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25329
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25329
  - https://downloads.wordpress.org/plugin/wp-with-spritz.zip
  - https://www.exploit-db.com/exploits/44544
  - https://www.vulncheck.com/advisories/wordpress-plugin-wp-with-spritz-remote-file-inclusion
rules:
  - title: Detect CVE-2018-25329 Exploitation via wp.spritz.content.filter.php
    description: Detects CVE-2018-25329 exploitation — RFI attempts targeting wp.spritz.content.filter.php with URL parameter containing directory traversal sequences or remote URLs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect WordPress Plugin Directory Traversal Attempts in URL Parameter
    description: Detects attempts to exploit directory traversal vulnerabilities in WordPress plugins via URL parameters.  This pattern is often used in RFI and LFI attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The WordPress WP with Spritz plugin, version 1.0, suffers from a remote file inclusion (RFI) vulnerability (CVE-2018-25329). This flaw enables unauthenticated attackers to read arbitrary files on the server. By crafting malicious GET requests to the `wp.spritz.content.filter.php` script and injecting file paths into the `url` parameter, attackers can bypass authentication mechanisms and access sensitive system files. This could include configuration files, credentials, and other data that could be leveraged for further malicious activities, such as privilege escalation or data exfiltration. The vulnerability allows attackers to directly read files from the compromised server.

## Attack Chain

1.  The attacker identifies a WordPress site using the vulnerable WP with Spritz plugin 1.0.
2.  The attacker crafts a malicious GET request targeting the `wp.spritz.content.filter.php` endpoint.
3.  The attacker injects a file path into the `url` parameter of the GET request. This path points to a file the attacker wishes to read on the server.
4.  The web server processes the request, and the vulnerable code in `wp.spritz.content.filter.php` includes the specified file without proper sanitization.
5.  The contents of the targeted file are exposed as part of the HTTP response.
6.  The attacker receives the HTTP response and extracts the file contents.
7.  The attacker analyzes the exfiltrated data, searching for sensitive information such as database credentials, API keys, or configuration details.
8.  The attacker uses the obtained information to further compromise the system or access other resources.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to read arbitrary files on the WordPress server. This may lead to the exposure of sensitive information, such as database credentials, configuration files, or even source code. The impact of this vulnerability can range from information disclosure to complete system compromise, depending on the sensitivity of the exposed files. The CVE has a CVSS v3.1 score of 7.5 (HIGH).

## Recommendation

*   Apply the provided Sigma rule `Detect CVE-2018-25329 Exploitation via wp.spritz.content.filter.php` to identify exploitation attempts by monitoring web server logs.
*   If the WP with Spritz plugin is installed, remove it from the WordPress installation until a patched version is available from the vendor.
*   Monitor web server logs for unusual GET requests targeting the `wp.spritz.content.filter.php` endpoint with suspicious `url` parameter values.
