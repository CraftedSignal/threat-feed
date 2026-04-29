---
title: ChurchCRM Path Traversal Vulnerability Leading to Remote Code Execution
slug: 2026-04-churchcrm-traversal
description: A path traversal vulnerability in ChurchCRM versions prior to 6.5.3 allows authenticated administrators to upload arbitrary files, leading to remote code execution by overwriting Apache .htaccess files.
date: "2026-04-07T18:16:41Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - path-traversal
  - rce
  - churchcrm
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-35573
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35573
rules:
  - title: ChurchCRM Suspicious File Upload
    description: Detects suspicious file uploads to ChurchCRM's backup directory with unusual extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: ChurchCRM .htaccess File Creation
    description: Detects the creation of .htaccess files in web directories, potentially indicating an attempt to modify web server behavior.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

ChurchCRM, an open-source church management system, is vulnerable to a path traversal attack affecting versions prior to 6.5.3. This vulnerability resides in the backup restore functionality, specifically within `src/ChurchCRM/Backup/RestoreJob.php`. Authenticated administrators can exploit this flaw by manipulating the `$rawUploadedFile['name']` parameter, which lacks proper sanitization. This allows for the upload of arbitrary files with attacker-controlled names to the `/var/www/html/tmp_attach/ChurchCRMBackups/` directory. Successful exploitation leads to remote code execution via overwriting Apache's `.htaccess` configuration files, effectively compromising the web server. Organizations using vulnerable versions of ChurchCRM are at risk of unauthorized access and control of their systems.

## Attack Chain

1.  An authenticated administrator logs into the ChurchCRM application.
2.  The administrator navigates to the backup restore functionality.
3.  The attacker crafts a malicious backup archive containing a crafted `.htaccess` file.
4.  The attacker uploads the malicious backup archive via the restore functionality, exploiting the path traversal vulnerability in `src/ChurchCRM/Backup/RestoreJob.php`. The `$rawUploadedFile['name']` parameter is manipulated to control the file's destination.
5.  The malicious `.htaccess` file is written to the web server's document root or a sensitive directory, such as `/var/www/html/`.
6.  The overwritten `.htaccess` file modifies the Apache web server's configuration, potentially enabling PHP execution for arbitrary file types or redirecting requests to attacker-controlled scripts.
7.  The attacker accesses a file (e.g., an image or text file) which is now parsed as PHP code due to the malicious `.htaccess` configuration.
8.  The attacker executes arbitrary code on the server, gaining remote code execution.

## Impact

Successful exploitation of this vulnerability allows attackers to gain complete control of the ChurchCRM web server. This can lead to data breaches, defacement of the website, and the potential to use the compromised server as a launchpad for further attacks within the network. Given the sensitive nature of data often stored in ChurchCRM systems (e.g., personal contact information, financial records), the compromise can have severe consequences for both the organization and its members. While the exact number of vulnerable installations is unknown, the widespread use of ChurchCRM makes this a significant threat.

## Recommendation

*   Upgrade ChurchCRM to version 6.5.3 or later to patch the vulnerability described in CVE-2026-35573.
*   Implement strict file upload validation and sanitization to prevent path traversal vulnerabilities in other web applications.
*   Monitor web server logs for suspicious file uploads to `/var/www/html/tmp_attach/ChurchCRMBackups/` directory, looking for unexpected file extensions using the "ChurchCRM Suspicious File Upload" Sigma rule.
*   Implement the "ChurchCRM .htaccess File Creation" Sigma rule to detect the creation of .htaccess files in web directories.
