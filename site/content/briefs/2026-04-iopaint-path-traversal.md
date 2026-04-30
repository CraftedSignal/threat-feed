---
title: Sanster IOPaint Path Traversal Vulnerability (CVE-2026-5258)
slug: 2026-04-iopaint-path-traversal
description: A path traversal vulnerability (CVE-2026-5258) exists in Sanster IOPaint 1.5.3, allowing remote attackers to read arbitrary files by manipulating the filename argument in the _get_file function within the File Manager component.
date: "2026-04-01T07:16:02Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - path traversal
  - cve-2026-5258
  - web application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5258
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5258
  - https://github.com/August829/CVEP/issues/11
  - https://vuldb.com/vuln/354448
rules:
  - title: Detect IOPaint Path Traversal Attempt
    description: Detects potential path traversal attempts targeting Sanster IOPaint by looking for suspicious URL encoded sequences in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect IOPaint Path Traversal via GET Request
    description: Detects path traversal attempts in IOPaint through GET requests by identifying 'filename' parameter manipulation with path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Sanster IOPaint version 1.5.3 is vulnerable to a path traversal flaw (CVE-2026-5258) within its File Manager component. The vulnerability resides in the `_get_file` function located in `iopaint/file_manager/file_manager.py`. By crafting a malicious request and manipulating the `filename` argument, an unauthenticated attacker can bypass directory restrictions and potentially read sensitive files on the server. Publicly available exploits exist, increasing the urgency for patching or mitigating this vulnerability. The vendor was notified but did not respond.

## Attack Chain

1.  An attacker identifies a Sanster IOPaint 1.5.3 instance running a vulnerable server.
2.  The attacker crafts a malicious HTTP request targeting the file retrieval endpoint of the `File Manager` component.
3.  Within the request, the attacker manipulates the `filename` parameter to include path traversal sequences (e.g., `../`, `..%2f`).
4.  The server-side application, specifically the `_get_file` function in `iopaint/file_manager/file_manager.py`, receives the request with the tainted `filename`.
5.  Due to insufficient input validation and sanitization, the application incorrectly constructs the file path.
6.  The application attempts to read a file from a location outside the intended directory, based on the attacker-controlled path.
7.  If successful, the application returns the contents of the arbitrary file in the HTTP response.
8.  The attacker receives the content of the targeted file, potentially containing sensitive information or configuration data.

## Impact

Successful exploitation of this path traversal vulnerability (CVE-2026-5258) allows an attacker to read arbitrary files on the server hosting Sanster IOPaint. This can lead to the disclosure of sensitive information, such as application source code, configuration files containing database credentials, or user data. The impact depends on the permissions of the user account running the application. If the application runs with elevated privileges, the attacker may be able to access system-level files, potentially leading to further compromise of the server.

## Recommendation

*   Deploy the Sigma rule `Detect IOPaint Path Traversal Attempt` to detect exploitation attempts based on suspicious URL encoding in web server logs.
*   Implement strict input validation and sanitization on the `filename` parameter within the `_get_file` function to prevent path traversal attacks as described in CVE-2026-5258.
*   Consider using a web application firewall (WAF) with rules designed to block path traversal attempts.
*   Upgrade to a patched version of Sanster IOPaint as soon as one becomes available to remediate CVE-2026-5258.
