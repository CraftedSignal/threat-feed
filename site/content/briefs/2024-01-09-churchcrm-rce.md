---
title: ChurchCRM Remote Code Execution via Backup Restore Vulnerability (CVE-2026-40484)
slug: 2024-01-09-churchcrm-rce
description: ChurchCRM versions before 7.2.0 are vulnerable to remote code execution (RCE) due to insufficient file extension filtering during database backup restoration, allowing an authenticated administrator to upload a crafted archive containing a PHP webshell that can be executed via HTTP requests.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-40484
  - ChurchCRM
  - Remote Code Execution
  - Web Shell
  - CSRF
vendors:
  - ChurchCRM
products:
  - ChurchCRM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: Server Software Component
cves:
  - id: CVE-2026-40484
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40484
rules:
  - title: Detect PHP Webshell Upload via Backup Restore
    description: Detects the creation of PHP files in web-accessible directories, indicative of a webshell upload, potentially related to CVE-2026-40484.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious HTTP Requests to Uploaded PHP Files
    description: Detects HTTP requests to PHP files within the Images directory after the reported vulnerability was exploited.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
  - title: Detect ChurchCRM backup restore lacking CSRF token
    description: Detects POST requests to the ChurchCRM restore endpoint without a valid CSRF token, indicative of a potential CSRF attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 3
---

ChurchCRM, an open-source church management system, is susceptible to remote code execution (RCE) in versions prior to 7.2.0. This vulnerability stems from the insecure handling of database backup restoration. Specifically, the `recursiveCopyDirectory()` function fails to adequately filter file extensions when extracting uploaded archive contents from the `Images/` directory, copying files into the web-accessible document root. An authenticated administrator can exploit this by uploading a malicious backup archive containing a PHP webshell. Due to the lack of file extension filtering, this webshell is written to a publicly accessible path, enabling attackers to execute arbitrary code on the server as the web server user via HTTP requests. The absence of CSRF token validation on the restore endpoint further exacerbates the issue, enabling cross-site request forgery (CSRF) attacks against authenticated administrators. This vulnerability is identified as CVE-2026-40484.

## Attack Chain

1.  Attacker gains valid administrator credentials to the ChurchCRM application.
2.  Attacker crafts a malicious backup archive containing a PHP webshell file (e.g., `shell.php`) within an `Images/` directory structure.
3.  The attacker uploads the crafted backup archive through the ChurchCRM administrative interface using the database backup restore functionality.
4.  The application's `recursiveCopyDirectory()` function extracts the archive contents without proper file extension filtering.
5.  The PHP webshell file (e.g., `shell.php`) is copied from the `Images/` directory within the archive to a publicly accessible directory in the web server's document root.
6.  The attacker leverages the lack of CSRF protection in the restore endpoint, possibly by tricking an administrator into triggering the restore via a malicious link or website.
7.  The attacker sends an HTTP request to the uploaded PHP webshell (e.g., `http://churchcrm.example.com/Images/shell.php?cmd=whoami`) to execute arbitrary code on the server.
8.  The web server executes the PHP code, granting the attacker remote code execution capabilities as the web server user.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the ChurchCRM server with the privileges of the web server user. This could lead to complete compromise of the server, data exfiltration (including sensitive church member data), defacement of the website, or further lateral movement within the network. Given the sensitive nature of data typically stored in church management systems, the impact can be severe.

## Recommendation

*   Upgrade ChurchCRM to version 7.2.0 or later to patch CVE-2026-40484 immediately.
*   Implement a web application firewall (WAF) rule to detect and block requests to potentially malicious PHP files uploaded to the `Images/` directory, specifically targeting HTTP requests with suspicious parameters like `cmd=`.
*   Deploy the Sigma rule detecting suspicious PHP file creation in web directories to identify potential webshell uploads.
*   Enable logging for web server access and error logs and monitor for unusual activity, especially related to the `Images/` directory.
