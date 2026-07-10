---
title: Chyrp Lite Path Traversal Vulnerability Leads to Remote Code Execution
slug: 2024-01-chyrp-lite-path-traversal
description: A path traversal vulnerability in Chyrp Lite blogging engine prior to version 2026.01 allows an administrator or a user with Change Settings permission to download arbitrary files, including configuration files containing database credentials, and overwrite critical system files, leading to remote code execution.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - chyrp-lite
  - path-traversal
  - rce
  - cve-2026-35174
vendors:
  - Chyrp
products:
  - Chyrp Lite
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-35174
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35174
rules:
  - title: Detect Chyrp Lite Path Traversal Attempts
    description: Detects suspicious requests containing path traversal sequences targeting the Chyrp Lite installation directory, indicating potential exploitation attempts of CVE-2026-35174.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1588
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Sensitive Chyrp Lite Configuration File
    description: Detects access attempts to the sensitive Chyrp Lite configuration file (`config.json.php`), which may indicate unauthorized access or data exfiltration.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chyrp Lite, an ultra-lightweight blogging engine, is vulnerable to a path traversal attack in versions prior to 2026.01. This vulnerability exists within the administration console, specifically affecting the handling of upload paths. An authenticated administrator, or a user with the 'Change Settings' permission, can manipulate the application to modify the designated uploads path to any directory on the server. This manipulation allows for the potential download of sensitive files, such as `config.json.php`, which contains database credentials. Furthermore, it enables the overwriting of critical system files. Successful exploitation of this vulnerability leads to remote code execution, making it a critical risk for organizations utilizing affected versions of Chyrp Lite. Update to version 2026.01 or later to remediate this vulnerability.

## Attack Chain

1. An attacker authenticates to the Chyrp Lite administration console, either as an administrator or as a user with 'Change Settings' permissions.
2. The attacker navigates to the settings page within the administration console.
3. The attacker modifies the uploads path setting, using path traversal techniques (e.g., "../") to point to an arbitrary directory on the server.
4. The attacker leverages the modified uploads path to download sensitive files, such as `config.json.php`, which contains database credentials. This can be achieved by uploading a file to the manipulated path, and then accessing it via a crafted URL, or by directly requesting the file if webserver access is permitted for that directory.
5. The attacker gains access to the database credentials stored in `config.json.php`.
6. The attacker uses the compromised database credentials to gain further access to the Chyrp Lite system.
7. The attacker leverages the file upload functionality, combined with the path traversal vulnerability, to overwrite critical system files with malicious code (e.g., PHP webshell).
8. The attacker executes the malicious code via a web request, achieving remote code execution on the server.

## Impact

Successful exploitation of CVE-2026-35174 allows an attacker to gain complete control of the Chyrp Lite server. This can lead to data breaches involving sensitive information stored in the database, defacement of the blog, or the server being used as a platform for further malicious activities. The CVSS v3.1 base score for this vulnerability is 9.1, indicating its critical severity. The number of potential victims depends on the number of organizations using vulnerable versions of Chyrp Lite, which is an ultra-lightweight blogging engine, suggesting a smaller installation base than larger CMS platforms.

## Recommendation

*   Immediately upgrade Chyrp Lite to version 2026.01 or later to patch CVE-2026-35174.
*   Monitor web server logs for suspicious requests containing path traversal sequences (e.g., "../") targeting the Chyrp Lite installation directory to detect exploitation attempts. Deploy the provided Sigma rule `Detect Chyrp Lite Path Traversal Attempts` to your SIEM.
*   Implement strict access control policies on the Chyrp Lite server, limiting the number of users with 'Change Settings' permissions.
*   Review the configuration of your Chyrp Lite installation to ensure proper file permissions and restrict web server access to sensitive files such as `config.json.php`. Deploy the provided Sigma rule `Detect Access to Sensitive Chyrp Lite Configuration File` to your SIEM.
