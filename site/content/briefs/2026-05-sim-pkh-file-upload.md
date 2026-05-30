---
title: SIM-PKH 2.4.1 Arbitrary File Upload Vulnerability (CVE-2018-25409)
slug: 2026-05-sim-pkh-file-upload
description: SIM-PKH 2.4.1 contains an arbitrary file upload vulnerability (CVE-2018-25409) that allows authenticated attackers to upload malicious PHP files via the fupload parameter through the aksi_pengurus.php endpoint, leading to remote code execution.
date: "2026-05-30T16:18:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - file-upload
  - remote-code-execution
  - web-application
products:
  - SIM-PKH
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2018-25409
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25409
  - CVE-2018-25409
rules:
  - title: Detect SIM-PKH Arbitrary File Upload (CVE-2018-25409)
    description: Detects CVE-2018-25409 exploitation — attempts to upload PHP files to the SIM-PKH application via the fupload parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect SIM-PKH PHP File Execution in foto Directory (CVE-2018-25409)
    description: Detects CVE-2018-25409 exploitation — access attempts to PHP files located in the foto directory, which may indicate successful exploitation of the file upload vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
rules_count: 2
---

SIM-PKH 2.4.1 is vulnerable to an arbitrary file upload vulnerability (CVE-2018-25409). Authenticated attackers can exploit this vulnerability by uploading malicious PHP files through the `fupload` parameter. The vulnerability exists within the `aksi_pengurus.php` endpoint, specifically when processing requests with `module=pengurus` and `act=update` parameters. Successful exploitation allows attackers to store PHP files in the `foto` directory, which are then executed as web scripts, potentially leading to remote code execution on the server. This poses a significant risk to organizations using the vulnerable software, as it could lead to complete compromise of the system.

## Attack Chain

1. The attacker authenticates to the SIM-PKH application.
2. The attacker crafts a malicious PHP file containing shell commands.
3. The attacker sends a POST request to `aksi_pengurus.php` with `module=pengurus` and `act=update`.
4. The POST request includes the malicious PHP file in the `fupload` parameter.
5. The application saves the uploaded PHP file in the `foto` directory.
6. The attacker determines the path to the uploaded file within the `foto` directory.
7. The attacker sends an HTTP request to the uploaded PHP file.
8. The server executes the PHP code, granting the attacker remote code execution.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the web server hosting SIM-PKH 2.4.1. This could lead to complete system compromise, including data theft, defacement of the website, or the deployment of further malicious payloads. The impact is significant due to the potential for unauthorized access and control of the affected system. There are no specific victim counts or sector information available from the provided source.

## Recommendation

*   Apply available patches or upgrade to a secure version of SIM-PKH to remediate CVE-2018-25409.
*   Implement the Sigma rule `Detect SIM-PKH Arbitrary File Upload (CVE-2018-25409)` to detect malicious file uploads.
*   Monitor web server logs for POST requests to `aksi_pengurus.php` containing PHP code in the `fupload` parameter.
*   Implement the Sigma rule `Detect SIM-PKH PHP File Execution in foto Directory (CVE-2018-25409)` to detect access attempts to uploaded PHP files.
