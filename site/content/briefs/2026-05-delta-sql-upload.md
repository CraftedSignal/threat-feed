---
title: 'CVE-2018-25412: Delta Sql 1.8.2 Arbitrary File Upload Vulnerability'
slug: 2026-05-delta-sql-upload
description: Delta Sql version 1.8.2 contains an arbitrary file upload vulnerability (CVE-2018-25412) that allows unauthenticated attackers to upload malicious files via crafted POST requests, potentially leading to remote code execution.
date: "2026-05-30T16:17:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - file-upload
  - rce
vendors:
  - Delta
products:
  - Sql 1.8.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: PHP'
cves:
  - id: CVE-2018-25412
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25412
rules:
  - title: Detect CVE-2018-25412 Exploitation — Malicious File Upload
    description: Detects CVE-2018-25412 exploitation — attempt to upload PHP file to docs_upload.php
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2018-25412 Exploitation — Suspicious POST Request
    description: Detects CVE-2018-25412 exploitation — suspicious POST request to docs_upload.php with unusual parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Delta Sql 1.8.2 is vulnerable to an arbitrary file upload vulnerability (CVE-2018-25412). An unauthenticated attacker can exploit this vulnerability by sending a crafted POST request to the `docs_upload.php` endpoint. The request must contain multipart form data specifically designed to bypass upload restrictions. Successful exploitation allows the attacker to upload arbitrary files, including PHP files, to the server's upload directory. This can lead to remote code execution (RCE) as the uploaded files can be accessed and executed by the web server. The impact is significant due to the ease of exploitation and the potential for complete system compromise.

## Attack Chain

1.  The attacker identifies a Delta Sql 1.8.2 instance.
2.  The attacker crafts a malicious PHP file containing arbitrary code to be executed on the server.
3.  The attacker crafts a POST request with multipart form data, targeting the `docs_upload.php` endpoint.
4.  The POST request is designed to bypass file type and size restrictions. The filename extension is set to `.php`
5.  The attacker sends the crafted POST request to the vulnerable server.
6.  The server saves the malicious PHP file to the upload directory.
7.  The attacker accesses the uploaded PHP file via a web browser, triggering its execution on the server.
8.  The attacker achieves remote code execution, potentially gaining full control of the server.

## Impact

Successful exploitation of CVE-2018-25412 allows an unauthenticated attacker to execute arbitrary code on the affected server. This can lead to complete system compromise, data theft, defacement, or denial-of-service. The lack of authentication makes this vulnerability particularly dangerous. Given the high CVSS score (9.8), immediate action is required to mitigate the risk.

## Recommendation

*   Apply any available patches or upgrades for Delta Sql to address CVE-2018-25412.
*   Implement strict file upload validation on the server to prevent arbitrary file uploads. Block uploads to `docs_upload.php` via the "Detect CVE-2018-25412 Exploitation — Malicious File Upload" Sigma rule.
*   Monitor web server logs for suspicious POST requests to `docs_upload.php` using the "Detect CVE-2018-25412 Exploitation — Suspicious POST Request" Sigma rule.
