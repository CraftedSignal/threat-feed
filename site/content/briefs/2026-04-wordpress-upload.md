---
title: 'WordPress Plugin Vulnerability: Arbitrary File Upload in Gerador de Certificados – DevApps'
slug: 2026-04-wordpress-upload
description: The Gerador de Certificados – DevApps WordPress plugin is vulnerable to arbitrary file uploads due to missing file type validation, potentially leading to remote code execution.
date: "2026-04-08T07:16:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - file-upload
  - remote-code-execution
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1584
    technique_name: Compromise Infrastructure
cves:
  - id: CVE-2026-4808
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4808
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/870bf5fe-00c6-48fe-b9e6-e8233c689b71?source=cve
rules:
  - title: Detect Access to PHP Files in WordPress Uploads Directory
    description: Detects HTTP requests attempting to execute PHP files within the wp-content/uploads directory, which could indicate exploitation of a file upload vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect Arbitrary File Uploads to WordPress Plugins Directory
    description: This rule detects suspicious POST requests to the WordPress plugins directory, which might indicate an attempt to upload malicious files.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Gerador de Certificados – DevApps plugin for WordPress, versions up to and including 1.3.6, contains an arbitrary file upload vulnerability (CVE-2026-4808). This flaw stems from a lack of file type validation within the `moveUploadedFile()` function. Authenticated users with administrator privileges or higher can exploit this vulnerability by uploading arbitrary files to the affected server. Successful exploitation could allow an attacker to execute arbitrary code on the server, leading to a complete system compromise. This vulnerability poses a significant threat to websites using the affected plugin, potentially impacting data confidentiality, integrity, and availability.

## Attack Chain

1. An attacker authenticates to the WordPress site with administrator-level privileges.
2. The attacker navigates to the Gerador de Certificados – DevApps plugin's upload functionality.
3. The attacker crafts a malicious file (e.g., a PHP file) with a disguised extension or no extension.
4. The attacker uploads the malicious file through the plugin's interface, bypassing the missing file type validation in the `moveUploadedFile()` function.
5. The plugin saves the file to a publicly accessible directory on the server.
6. The attacker identifies the location of the uploaded file.
7. The attacker sends an HTTP request to the uploaded file's location.
8. The server executes the malicious code within the uploaded file, granting the attacker remote code execution capabilities.

## Impact

Successful exploitation of this vulnerability allows attackers with administrator privileges to upload arbitrary files to the web server. This can lead to remote code execution, potentially allowing the attacker to gain full control of the WordPress website and the underlying server. This could lead to data theft, website defacement, or use of the server for malicious purposes such as hosting phishing sites or launching attacks against other systems. The number of affected sites is potentially very large.

## Recommendation

*   Upgrade the Gerador de Certificados – DevApps plugin to the latest version, which includes a fix for CVE-2026-4808.
*   Implement web server configurations to prevent the execution of scripts in upload directories.
*   Enable web server logging and monitor for suspicious file uploads and access attempts to unusual file types.
*   Deploy the Sigma rule to detect attempts to access PHP files within the wp-content/uploads directory.
