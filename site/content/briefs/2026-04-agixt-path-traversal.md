---
title: AGiXT Path Traversal Vulnerability (CVE-2026-39981)
slug: 2026-04-agixt-path-traversal
description: AGiXT versions prior to 1.9.2 are vulnerable to path traversal (CVE-2026-39981) due to insufficient validation in the safe_join() function, allowing authenticated attackers to read, write, or delete arbitrary files.
date: "2026-04-09T18:17:02Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - path-traversal
  - cve
  - agixt
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-39981
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39981
  - https://github.com/Josh-XT/AGiXT/commit/2079ea5a88fa671a921bf0b5eba887a5a1b73d5f
  - https://github.com/Josh-XT/AGiXT/releases/tag/v1.9.2
  - https://github.com/Josh-XT/AGiXT/security/advisories/GHSA-5gfj-64gh-mgmw
rules:
  - title: Detect AGiXT Path Traversal Attempt via Web Logs
    description: Detects potential path traversal attempts targeting AGiXT by monitoring web server logs for suspicious URL patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect AGiXT Arbitrary File Write via Web Logs
    description: Detects potential arbitrary file write attempts by monitoring web server logs for suspicious POST requests with file extensions commonly used for configuration or code.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AGiXT, a dynamic AI Agent Automation Platform, contains a critical vulnerability (CVE-2026-39981) affecting versions prior to 1.9.2. The vulnerability lies in the `safe_join()` function within the `essential_abilities` extension. This function fails to adequately validate file paths, creating an opportunity for authenticated attackers to perform directory traversal attacks. By exploiting this flaw, an attacker can manipulate file paths to access files outside the designated agent workspace, resulting in arbitrary file read, write, or deletion capabilities on the server hosting the AGiXT instance. This issue was addressed and resolved in AGiXT version 1.9.2. This vulnerability could allow an attacker to gain complete control over the AGiXT server.

## Attack Chain

1.  The attacker authenticates to the AGiXT application.
2.  The attacker crafts a malicious request targeting the `safe_join()` function within the `essential_abilities` extension.
3.  The malicious request includes directory traversal sequences (e.g., `../`) to navigate outside the intended agent workspace.
4.  The `safe_join()` function fails to properly sanitize the input, allowing the traversal sequences to take effect.
5.  The attacker gains the ability to read arbitrary files on the server using the path traversal.
6.  The attacker exploits the ability to write to arbitrary files to inject malicious code or overwrite existing system files.
7.  The attacker leverages the write access to establish persistence, potentially by modifying system startup scripts or scheduled tasks.
8.  The attacker achieves arbitrary code execution on the server hosting the AGiXT instance, potentially leading to complete system compromise.

## Impact

Successful exploitation of CVE-2026-39981 can lead to complete compromise of the AGiXT server. An attacker could gain unauthorized access to sensitive data, modify system configurations, install malware, or disrupt services. This vulnerability has a CVSS v3.1 score of 8.8, indicating a high severity. The impact could be significant for organizations relying on AGiXT for critical operations, potentially leading to data breaches, financial losses, and reputational damage. The number of victims and specific sectors targeted are currently unknown.

## Recommendation

*   Upgrade AGiXT to version 1.9.2 or later to remediate CVE-2026-39981 (references: https://github.com/Josh-XT/AGiXT/releases/tag/v1.9.2).
*   Implement input validation and sanitization measures to prevent directory traversal attacks.
*   Monitor AGiXT application logs for suspicious file access attempts and path manipulation sequences.
*   Deploy the Sigma rules below to your SIEM to detect potential exploitation attempts targeting CVE-2026-39981.
