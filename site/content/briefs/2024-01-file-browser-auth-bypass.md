---
title: File Browser Proxy Authentication Bypass Vulnerability (CVE-2026-35607)
slug: 2024-01-file-browser-auth-bypass
description: File Browser versions before 2.63.1 improperly grant execution capabilities to new users created via proxy authentication, leading to privilege escalation.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - file-browser
  - authentication-bypass
  - privilege-escalation
  - cve-2026-35607
vendors:
  - File Browser
products:
  - File Browser
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35607
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35607
rules:
  - title: Detect File Browser Unauthorized Command Execution
    description: Detects potential exploitation of CVE-2026-35607 by monitoring for process creation events initiated by File Browser with suspicious command line arguments.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect File Browser Web Shell Upload
    description: Detects potential web shell uploads through File Browser by monitoring file creation events with suspicious extensions in the File Browser directory.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

File Browser is a file management interface that allows users to upload, delete, preview, rename, and edit files. A vulnerability, identified as CVE-2026-35607, exists in versions prior to 2.63.1. This flaw stems from inconsistent application of a fix intended to restrict execution permissions for self-registered users. While the fix was correctly implemented for the signup handler (commit b6a4fb1), it was not applied to the proxy authentication handler. As a result, users automatically created upon their first successful proxy authentication login are inadvertently granted execution capabilities based on global defaults. This contradicts the intended security measure of preventing automatic accounts from inheriting execution rights. This vulnerability allows unauthorized users to execute commands, potentially leading to system compromise. The issue is resolved in File Browser version 2.63.1.

## Attack Chain

1. A user attempts to access the File Browser interface via proxy authentication.
2. The File Browser instance, running a version prior to 2.63.1, authenticates the user through the proxy.
3. If the user does not already exist, the application automatically creates a new user account.
4. Due to the missing fix in the proxy authentication handler, the newly created user account is granted execution permissions.
5. The attacker leverages the granted execution permissions to execute arbitrary commands on the server.
6. These commands could be used to read sensitive files, modify system configurations, or install malicious software.
7. The attacker uses the file management interface to upload a malicious script.
8. The attacker executes the malicious script, achieving arbitrary code execution on the server, potentially leading to data exfiltration or system takeover.

## Impact

Successful exploitation of CVE-2026-35607 allows unauthenticated or newly authenticated users to gain unauthorized execution privileges within the File Browser application. This can lead to the execution of arbitrary commands, potentially compromising the server hosting the application. The CVSS v3.1 base score for this vulnerability is 8.1, indicating a high level of severity. Depending on the server configuration, this could result in data breaches, system downtime, or complete system takeover.

## Recommendation

*   Upgrade File Browser to version 2.63.1 or later to remediate CVE-2026-35607.
*   Implement the Sigma rule "Detect File Browser Unauthorized Command Execution" to identify potential exploitation attempts by monitoring for suspicious process creation events initiated by the File Browser process.
*   Review and restrict the default execution permissions for File Browser to minimize the impact of potential exploits.
*   Monitor web server logs for unusual activity associated with File Browser, specifically HTTP requests related to file uploads and execution.
