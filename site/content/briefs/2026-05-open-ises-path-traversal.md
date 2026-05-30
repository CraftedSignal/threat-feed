---
title: Open ISES Project 3.30A Unauthenticated Path Traversal Vulnerability
slug: 2026-05-open-ises-path-traversal
description: Open ISES Project 3.30A is vulnerable to path traversal (CVE-2018-25408), allowing unauthenticated attackers to download arbitrary files by manipulating the filename parameter in the ajax/download.php endpoint, potentially exposing configuration and system files.
date: "2026-05-30T16:18:41Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - web-application
vendors:
  - Open ISES Project
products:
  - Open ISES Project 3.30A
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2018-25408
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25408
rules:
  - title: Detect Path Traversal in Open ISES Project
    description: Detects CVE-2018-25408 exploitation - Path traversal attempts in the filename parameter of the ajax/download.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Double Encoding in Open ISES Project Path Traversal
    description: Detects CVE-2018-25408 exploitation - Double-encoded path traversal attempts in Open ISES Project ajax/download.php.
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

Open ISES Project version 3.30A is susceptible to a path traversal vulnerability, designated as CVE-2018-25408. This flaw resides in the ajax/download.php endpoint and allows unauthenticated remote attackers to retrieve arbitrary files from the server. By crafting malicious requests containing directory traversal sequences, such as "../", within the filename parameter, an attacker can bypass intended access restrictions and potentially gain access to sensitive information like configuration files and system files. This vulnerability enables attackers to read local files without authentication.

## Attack Chain

1.  The attacker identifies the vulnerable ajax/download.php endpoint.
2.  The attacker crafts an HTTP GET or POST request to the ajax/download.php endpoint.
3.  The attacker injects a path traversal sequence (e.g., "../../../") into the filename parameter of the request.
4.  The server processes the request without proper validation of the filename parameter.
5.  The server attempts to read the file specified by the manipulated filename parameter, traversing directories outside the intended scope.
6.  If successful, the contents of the targeted file (e.g., a configuration file) are returned in the HTTP response.
7.  The attacker parses the response to extract the contents of the file.
8.  The attacker uses the leaked information (e.g. credentials, internal IP addresses) to further compromise the system or network.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2018-25408) allows unauthorized access to sensitive files on the Open ISES Project server. This could lead to the disclosure of confidential information, such as database credentials, API keys, or internal system configurations. The impact could range from information leakage to a complete compromise of the affected system, depending on the sensitivity of the exposed files.

## Recommendation

*   Apply available patches or updates from Open ISES Project to address CVE-2018-25408 and remediate the path traversal vulnerability in the ajax/download.php endpoint.
*   Deploy the Sigma rule `Detect Path Traversal in Open ISES Project` to identify exploitation attempts against the ajax/download.php endpoint by monitoring for directory traversal sequences in the filename parameter.
*   Implement strict input validation and sanitization on the filename parameter within the ajax/download.php endpoint to prevent path traversal attacks.
*   Review and restrict file access permissions on the server to limit the impact of successful path traversal exploitation.
