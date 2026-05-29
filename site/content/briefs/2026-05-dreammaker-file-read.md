---
title: DreamMaker Arbitrary File Read Vulnerability (CVE-2026-10073)
slug: 2026-05-dreammaker-file-read
description: DreamMaker by Interinfo is vulnerable to arbitrary file read via relative path traversal, allowing unauthenticated attackers to download arbitrary system files.
date: "2026-05-29T14:18:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - arbitrary file read
  - path traversal
vendors:
  - Interinfo
products:
  - DreamMaker
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1030
    technique_name: Data Source
cves:
  - id: CVE-2026-10073
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10073
  - https://www.twcert.org.tw/en/cp-139-10946-1127f-2.html
  - https://www.twcert.org.tw/tw/cp-132-10943-8fb00-1.html
rules:
  - title: Detect CVE-2026-10073 Attempted Exploitation via Path Traversal
    description: Detects CVE-2026-10073 exploitation attempts by identifying HTTP requests with relative path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1030
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-10073 Successful File Read via Web Server Logs
    description: Detects CVE-2026-10073 exploitation by monitoring web server logs for successful HTTP requests (status code 200) where relative path traversal was used.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1030
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

DreamMaker, developed by Interinfo, is affected by an arbitrary file read vulnerability (CVE-2026-10073). This vulnerability allows unauthenticated, local attackers to exploit relative path traversal to download arbitrary system files. The vulnerability arises from insufficient input validation when handling file paths, enabling attackers to access sensitive files outside the intended directory. Exploitation requires a local attacker due to the relative path traversal nature of the vulnerability. Successful exploitation allows the attacker to read potentially sensitive information from the affected system.

## Attack Chain

1.  Attacker identifies a vulnerable DreamMaker installation.
2.  Attacker crafts a malicious request containing a relative path traversal sequence (e.g., `../../../../etc/passwd`).
3.  The crafted request is sent to the vulnerable endpoint.
4.  DreamMaker processes the request without proper validation of the file path.
5.  The application attempts to read the file specified by the manipulated path.
6.  The operating system accesses the file due to insufficient sanitization.
7.  The contents of the file are returned to the attacker.
8.  Attacker gains unauthorized access to sensitive information.

## Impact

Successful exploitation of CVE-2026-10073 allows an unauthenticated attacker to read arbitrary files from the system. This could lead to the exposure of sensitive configuration files, credentials, or other confidential data. The impact is high due to the potential for complete system compromise if critical files are accessed.

## Recommendation

*   Apply available patches or updates provided by Interinfo for DreamMaker to remediate CVE-2026-10073.
*   Implement input validation and sanitization measures within DreamMaker to prevent relative path traversal attacks.
*   Monitor web server logs for suspicious requests containing relative path traversal sequences, as detected by the Sigma rule "Detect CVE-2026-10073 Attempted Exploitation via Path Traversal".
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
