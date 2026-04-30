---
title: LORIS Directory Traversal Vulnerability
slug: 2026-04-loris-traversal
description: LORIS, a neuroimaging research data management web application, is vulnerable to directory traversal (CVE-2026-35446) due to an incorrect order of operations in the FilesDownloadHandler, allowing authenticated attackers to access unauthorized files.
date: "2026-04-08T19:25:24Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - directory-traversal
  - web-application
  - neuroimaging
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35446
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35446
  - https://github.com/aces/Loris/security/advisories/GHSA-47jj-7xfg-8759
rules:
  - title: Detect LORIS Directory Traversal Attempt
    description: Detects attempts to exploit the directory traversal vulnerability (CVE-2026-35446) in LORIS by monitoring for '..' sequences in file download requests.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
  - title: Detect LORIS File Download Handler Access
    description: Detects access to the LORIS FilesDownloadHandler which is the target of CVE-2026-35446.
    platform: sigma
    severity: informational
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

LORIS (Longitudinal Online Research and Imaging System) is a self-hosted web application designed for data and project management in neuroimaging research. Versions 24.0.0 up to, but not including, 27.0.3 and 28.0.1 contain a directory traversal vulnerability (CVE-2026-35446) in the FilesDownloadHandler. This flaw stems from an incorrect order of operations, potentially enabling an attacker to escape the intended download directories and access sensitive files. Successful exploitation requires authentication and could lead to unauthorized access to sensitive research data. Users are advised to upgrade to versions 27.0.3 or 28.0.1 to mitigate this vulnerability. This vulnerability impacts organizations utilizing LORIS for managing sensitive neuroimaging data, potentially exposing research data.

## Attack Chain

1. An attacker authenticates to the LORIS web application with valid credentials.
2. The attacker crafts a malicious HTTP request to the `FilesDownloadHandler`.
3. The crafted request includes a manipulated file path designed to traverse directories outside the intended download directory.
4. The `FilesDownloadHandler` processes the request with an incorrect order of operations when validating the file path.
5. The application bypasses the intended directory restrictions due to the flawed validation process.
6. The attacker gains access to files and directories outside of the designated download directory.
7. The attacker reads sensitive data, including neuroimaging data, project files, or configuration files.
8. The attacker may exfiltrate sensitive data for malicious purposes, such as espionage or sale on the dark web.

## Impact

Successful exploitation of this directory traversal vulnerability (CVE-2026-35446) in LORIS could lead to unauthorized access to sensitive neuroimaging research data. The number of affected organizations is unknown, but any organization using LORIS versions 24.0.0 to before 27.0.3 and 28.0.1 is potentially vulnerable. The impact includes data breaches, intellectual property theft, and potential compromise of patient privacy if patient data is stored within the LORIS system.

## Recommendation

*   Upgrade LORIS to version 27.0.3 or 28.0.1 to remediate CVE-2026-35446, as indicated in the overview.
*   Implement the "Detect LORIS Directory Traversal Attempt" Sigma rule to monitor for suspicious file download requests.
*   Review web server access logs for unusual file download patterns or attempts to access files outside the intended download directories using the file_event log source to detect potential exploitation attempts.
