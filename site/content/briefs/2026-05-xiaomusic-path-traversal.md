---
title: xiaomusic Path Traversal Vulnerability (CVE-2026-10108)
slug: 2026-05-xiaomusic-path-traversal
description: xiaomusic v0.5.7 contains an unauthenticated path traversal vulnerability (CVE-2026-10108) in the GET /music/{file_path:path} endpoint, allowing unauthenticated attackers to read arbitrary files outside the intended music directory by exploiting an incomplete path prefix check.
date: "2026-05-29T18:19:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - CVE-2026-10108
products:
  - xiaomusic
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-10108
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10108
rules:
  - title: Detects CVE-2026-10108 Exploitation — xiaomusic Path Traversal Attempt
    description: Detects CVE-2026-10108 exploitation — Path traversal attempts in xiaomusic via the /music/ endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-10108 Exploitation — xiaomusic Path Traversal GET Request
    description: Detects CVE-2026-10108 exploitation — HTTP GET requests to the `/music` endpoint containing common path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

xiaomusic v0.5.7 is vulnerable to a path traversal vulnerability, identified as CVE-2026-10108. This flaw resides in the GET /music/{file_path:path} endpoint and stems from an insufficient path prefix check. An unauthenticated attacker can exploit this vulnerability to read sensitive files outside of the intended music directory. The vulnerability is due to the application failing to properly validate the requested file path against a defined music directory, allowing for traversal sequences to bypass the path restriction. Specifically, the flawed prefix check lacks a trailing separator in its comparison logic, enabling requests for files in sibling directories that share the initial prefix.

## Attack Chain

1.  An unauthenticated attacker identifies the vulnerable GET /music/{file_path:path} endpoint in xiaomusic v0.5.7.
2.  The attacker crafts a malicious HTTP GET request targeting the vulnerable endpoint. The request includes a file path designed to traverse outside of the intended music directory.
3.  The crafted file path utilizes directory traversal sequences such as "../" to navigate to parent directories.
4.  The incomplete path prefix check in xiaomusic fails to properly validate the manipulated path due to the missing trailing separator.
5.  The server processes the malicious request, granting access to files and directories outside of the intended music folder.
6.  The attacker retrieves sensitive files from the server, such as configuration files or application source code.
7.  The attacker analyzes the exfiltrated files for sensitive information, such as credentials or API keys.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to read arbitrary files on the server. This could lead to the disclosure of sensitive information such as configuration files, source code, or user data. The CVSS v3.1 base score for this vulnerability is 7.5, indicating a high severity. There is no information about the number of victims, sectors targeted, but the impact could be significant depending on the sensitivity of the data stored on the vulnerable server.

## Recommendation

*   Apply appropriate input validation and sanitization to prevent path traversal attacks.
*   Deploy the Sigma rule to detect path traversal attempts targeting the `/music` endpoint.
*   Upgrade xiaomusic to a patched version that addresses CVE-2026-10108.
*   Implement regular security audits and penetration testing to identify and remediate vulnerabilities.
