---
title: Weaver E-office Unauthenticated Arbitrary File Upload Vulnerability
slug: 2024-01-weaver-eoffice-upload
description: Weaver E-office versions prior to 10.0_20221201 are vulnerable to unauthenticated arbitrary file upload in the OfficeServer.php endpoint, allowing attackers to upload PHP webshells and achieve remote code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2022-50993
  - file-upload
  - webshell
  - rce
  - e-office
vendors:
  - Weaver
products:
  - E-office (< 10.0_20221201)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2022-50993
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-50993
rules:
  - title: Detect Weaver E-office Webshell Upload
    description: Detects attempts to upload PHP webshells via the OfficeServer.php endpoint in Weaver E-office.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1505.001
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious PHP File Access in Weaver E-office Document Directory
    description: Detects HTTP GET requests to PHP files within the Weaver E-office document directory, which may indicate webshell execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Weaver E-office, a web-based office automation system, is vulnerable to an unauthenticated arbitrary file upload vulnerability (CVE-2022-50993) affecting versions prior to 10.0_20221201. The vulnerability exists within the `OfficeServer.php` endpoint, allowing remote attackers to upload arbitrary files without authentication. This is achieved by sending multipart POST requests with manipulated filenames and content types. The Shadowserver Foundation observed initial exploitation evidence on October 10, 2022. Successful exploitation enables attackers to upload malicious PHP webshells to the Document directory and execute them via HTTP GET requests, leading to remote code execution on the affected server as the web server user. This can compromise the confidentiality, integrity, and availability of the E-office system and the underlying server.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP POST request to the `OfficeServer.php` endpoint.
2. The POST request includes a multipart form with a file upload field.
3. The attacker sets an arbitrary filename for the uploaded file, typically with a `.php` extension.
4. The attacker disguises the content type of the uploaded file to bypass basic server-side checks.
5. The server saves the uploaded file (a PHP webshell) to the Document directory.
6. The attacker sends an HTTP GET request to the uploaded PHP webshell file.
7. The web server executes the PHP code within the uploaded file.
8. The attacker achieves remote code execution as the web server user, enabling further malicious activities.

## Impact

Successful exploitation of CVE-2022-50993 allows an unauthenticated attacker to execute arbitrary code on the affected Weaver E-office server. This can lead to complete system compromise, data theft, modification of sensitive data, and disruption of services. The vulnerability has a CVSS v3.1 base score of 9.8, indicating its critical severity. While the number of victims and specific sectors targeted are not detailed, organizations using vulnerable versions of Weaver E-office are at high risk.

## Recommendation

*   Upgrade Weaver E-office to version 10.0_20221201 or later to patch CVE-2022-50993.
*   Deploy the Sigma rule "Detect Weaver E-office Webshell Upload" to detect malicious PHP file uploads to the `OfficeServer.php` endpoint.
*   Monitor web server access logs for requests to the Document directory with `.php` extensions, indicative of webshell execution.
*   Implement web application firewall (WAF) rules to block suspicious POST requests to `OfficeServer.php` with arbitrary file upload attempts.
