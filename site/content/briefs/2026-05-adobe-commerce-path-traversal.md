---
title: Adobe Commerce Path Traversal Vulnerability (CVE-2026-34653)
slug: 2026-05-adobe-commerce-path-traversal
description: Adobe Commerce versions 2.4.9-beta1, 2.4.8-p4, 2.4.7-p9, 2.4.6-p14, 2.4.5-p16, 2.4.4-p17 and earlier are vulnerable to a path traversal (CVE-2026-34653) allowing authenticated administrators to read and write arbitrary files.
date: "2026-05-12T20:21:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - web-application
  - adobe-commerce
vendors:
  - Adobe
products:
  - Commerce
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-34653
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34653
rules:
  - title: Detect Adobe Commerce Path Traversal Attempt
    description: Detects CVE-2026-34653 exploitation attempt — Path traversal attempts in Adobe Commerce via common directory traversal sequences
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Adobe Commerce File Write via Path Traversal
    description: Detects CVE-2026-34653 exploitation — File creation or modification in web directories after a detected path traversal attempt
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Adobe Commerce versions 2.4.9-beta1, 2.4.8-p4, 2.4.7-p9, 2.4.6-p14, 2.4.5-p16, and 2.4.4-p17 and earlier are susceptible to a path traversal vulnerability identified as CVE-2026-34653. This flaw allows an attacker with administrative privileges to bypass directory restrictions and gain unauthorized access to the file system. Successful exploitation could lead to arbitrary file read and write operations, potentially compromising sensitive data or system integrity. This vulnerability poses a significant risk to organizations utilizing affected versions of Adobe Commerce, as it could lead to data breaches, system compromise, and unauthorized modifications.

## Attack Chain

1. An attacker gains valid administrative credentials for the Adobe Commerce platform.
2. The attacker authenticates to the Adobe Commerce administrative panel.
3. The attacker crafts a malicious request targeting a file management function.
4. The request includes a path traversal sequence (e.g., "../") in a filename or path parameter.
5. The application fails to properly sanitize the path, allowing the traversal sequence to resolve to a location outside the intended directory.
6. The attacker leverages the path traversal to read sensitive configuration files, such as database credentials or API keys.
7. Alternatively, the attacker uses the path traversal to write malicious code (e.g., a PHP webshell) to a publicly accessible directory.
8. The attacker accesses the webshell via a web browser, achieving remote code execution on the server.

## Impact

Successful exploitation of CVE-2026-34653 allows an authenticated administrator to read and write arbitrary files on the Adobe Commerce server. This can lead to the exposure of sensitive data, such as customer information, financial records, and internal configurations. Furthermore, attackers can leverage this vulnerability to achieve remote code execution by writing malicious files to the server, potentially leading to a complete system compromise.

## Recommendation

*   Upgrade Adobe Commerce to a patched version that addresses CVE-2026-34653.
*   Implement the Sigma rule `Detect Adobe Commerce Path Traversal Attempt` to detect exploitation attempts.
*   Review and restrict administrative access to the Adobe Commerce platform to only authorized personnel.
*   Monitor web server logs for suspicious path traversal sequences in HTTP requests.
*   Apply principle of least privilege to file system permissions.
