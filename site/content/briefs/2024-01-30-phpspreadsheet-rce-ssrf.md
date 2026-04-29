---
title: PhpSpreadsheet SSRF and RCE Vulnerability via IOFactory::load
slug: 2024-01-30-phpspreadsheet-rce-ssrf
description: PhpSpreadsheet is vulnerable to Server-Side Request Forgery (SSRF) and Remote Code Execution (RCE) due to improper validation of filenames in the IOFactory::load function, exploitable via PHP wrappers like `phar://` and `ftp://`.
date: "2024-01-30T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - phpspreadsheet
  - ssrf
  - rce
  - php
  - deserialization
vendors:
  - PhpOffice
products:
  - PhpSpreadsheet
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
references:
  - https://github.com/advisories/GHSA-q4q6-r8wh-5cgh
rules:
  - title: Detect PhpSpreadsheet Phar Wrapper RCE Attempt
    description: Detects attempts to exploit the PhpSpreadsheet RCE vulnerability by monitoring process creation events with command lines containing 'phar://' and 'php'.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - process_creation
      - windows
  - title: Detect PhpSpreadsheet FTP Wrapper SSRF Attempt
    description: Detects attempts to exploit the PhpSpreadsheet SSRF vulnerability by monitoring network connections with destination ports on FTP protocol and source process be php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

PhpSpreadsheet, a widely used PHP library for reading and writing spreadsheet files, is susceptible to a critical vulnerability that can lead to both Server-Side Request Forgery (SSRF) and Remote Code Execution (RCE). The vulnerability stems from insufficient validation of the `$filename` parameter passed to the `IOFactory::load` function. When this parameter is user-controlled, attackers can leverage PHP wrappers such as `ftp://`, `phar://`, and `ssh2.sftp://` to bypass the `is_file` check, leading to malicious file inclusion or arbitrary code execution. This flaw affects versions up to and including 1.30.2, as well as versions 2.0.0 through 5.5.0. Exploitation can occur even if the specified file inside the phar archive does not exist or is not a supported file type, potentially masking the attack. Due to PhpSpreadsheet's widespread use in other popular libraries like `maatwebsite/excel` and `sonata-project/exporter`, the impact of this vulnerability is significant.

## Attack Chain

1.  An attacker crafts a malicious phar archive (`exploit.xlsx`) containing a PHP object with a `__destruct` method that executes arbitrary code via `shell_exec`.
2.  The attacker hosts the malicious phar archive on a web server or makes it accessible through other means.
3.  The attacker crafts a request to a vulnerable web application using PhpSpreadsheet, providing a `phar://` URL (e.g., `phar://exploit.xlsx/whatever`) as the `$filename` parameter to `IOFactory::load`.
4.  `IOFactory::load` attempts to load the file specified in the `$filename` parameter, which passes through the vulnerable `is_file` check.
5.  The `phar://` wrapper triggers PHP's phar extension, which deserializes the metadata within the `exploit.xlsx` archive.
6.  Deserialization of the malicious PHP object triggers the `__destruct` method, executing the attacker's arbitrary code via `shell_exec`, achieving RCE. The code creates `/tmp/poc.txt` in the example.
7. Alternatively, the attacker provides an `ftp://` URL to `IOFactory::load`, pointing to an attacker-controlled FTP server.
8.  The vulnerable `is_file` check allows the `ftp://` connection, leading to an SSRF vulnerability where the server running PhpSpreadsheet connects to the attacker's specified FTP server.

## Impact

Successful exploitation of this vulnerability can lead to a range of severe consequences. Remote Code Execution (RCE) allows an attacker to execute arbitrary commands on the server, potentially leading to complete system compromise. The SSRF vulnerability enables an attacker to probe internal network resources, potentially exposing sensitive information or allowing further attacks on internal systems. Given PhpSpreadsheet's use in numerous web applications and frameworks, a successful attack could impact a large number of users and organizations. Example impact includes attackers gaining initial access to internal applications.

## Recommendation

*   Apply the suggested mitigations by either checking for PHP wrappers in the filename before calling `is_file` or by using `realpath` to ensure a clean absolute path (see code snippets in the advisory).
*   Deploy the Sigma rule `Detect_PhpSpreadsheet_Phar_Wrapper` to detect attempts to exploit the RCE vulnerability by monitoring process creation events with command lines containing "phar://" and `php`.
*   Deploy the Sigma rule `Detect_PhpSpreadsheet_Ftp_Wrapper` to detect attempts to exploit the SSRF vulnerability by monitoring network connections with destination ports on FTP protocol (21) and file paths contain ftp.
*   Monitor web server logs for requests containing the `phar://` or `ftp://` schemes in the filename parameter to `IOFactory::load`.
