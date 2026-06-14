---
title: DreamMaker Arbitrary File Upload Vulnerability (CVE-2026-10072)
slug: 2026-05-dreammaker-file-upload
description: DreamMaker by Interinfo is vulnerable to arbitrary file upload, allowing privileged remote attackers to upload and execute web shell backdoors, enabling arbitrary code execution on the server.
date: "2026-05-29T14:18:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - arbitrary-file-upload
  - web-shell
  - code-execution
vendors:
  - Interinfo
products:
  - DreamMaker
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2026-10072
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10072
  - https://www.twcert.org.tw/en/cp-139-10946-1127f-2.html
  - https://www.twcert.org.tw/tw/cp-132-10943-8fb00-1.html
rules:
  - title: Detects CVE-2026-10072 Exploitation - Web Shell Upload via DreamMaker
    description: Detects attempts to execute web shells uploaded via the DreamMaker arbitrary file upload vulnerability (CVE-2026-10072) by monitoring for HTTP requests to common web shell file extensions.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detects CVE-2026-10072 Exploitation - Upload directory traversal attempt
    description: Detects CVE-2026-10072 exploitation - Path traversal in URI leading to upload directory
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Interinfo's DreamMaker is susceptible to an arbitrary file upload vulnerability (CVE-2026-10072). This flaw enables attackers with privileged access to upload and execute malicious web shell backdoors onto the server. Successful exploitation of this vulnerability can lead to arbitrary code execution on the affected server, potentially compromising the entire system and any data stored on it. Defenders need to ensure that DreamMaker installations are properly secured to prevent unauthorized file uploads.

## Attack Chain

1. Attacker authenticates to the DreamMaker application with privileged credentials.
2. Attacker identifies the file upload functionality within the DreamMaker application.
3. Attacker crafts a malicious web shell (e.g., a PHP script) designed for remote code execution.
4. Attacker leverages the arbitrary file upload vulnerability to upload the malicious web shell to a publicly accessible directory on the server.
5. The application fails to properly validate or sanitize the uploaded file, allowing it to be stored with a predictable name and location.
6. Attacker sends an HTTP request to the uploaded web shell (e.g., `http://example.com/uploads/shell.php`).
7. The web server executes the web shell, granting the attacker remote code execution capabilities.
8. Attacker uses the executed code to perform malicious actions, such as accessing sensitive data, installing malware, or pivoting to other systems.

## Impact

Successful exploitation of CVE-2026-10072 can lead to complete compromise of the DreamMaker server. An attacker with code execution capabilities can gain access to sensitive data, modify system files, install persistent backdoors, or use the compromised server as a launching point for further attacks against the internal network. The arbitrary code execution can lead to significant data breaches and service disruption.

## Recommendation

*   Apply available patches or updates from Interinfo for DreamMaker to address CVE-2026-10072.
*   Implement strict file upload validation and sanitization measures to prevent the upload of malicious files.
*   Monitor web server logs for suspicious requests to uploaded files, as covered by the provided Sigma rule.
*   Restrict access to file upload functionality to only authorized users with a legitimate need for it.
*   Deploy a web application firewall (WAF) with rules to detect and block malicious file upload attempts.
