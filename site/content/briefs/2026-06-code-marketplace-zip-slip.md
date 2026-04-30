---
title: Coder Code-Marketplace Zip Slip Vulnerability
slug: 2026-06-code-marketplace-zip-slip
description: A Zip Slip vulnerability in coder/code-marketplace allows authenticated users to upload malicious VSIX files containing path traversal entries, leading to arbitrary file writes outside the extension directory and potentially enabling persistence.
date: "2026-04-04T06:29:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - zip-slip
  - path-traversal
  - code-marketplace
  - persistence
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-8x9r-hvwg-c55h
  - https://coder.com/security/policy
  - https://github.com/coder/code-marketplace/releases/tag/v2.4.2
rules:
  - title: Detect Suspicious File Creation in Sensitive Directories
    description: Detects the creation of new files in sensitive directories, potentially indicating exploitation of path traversal vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.004
    data_sources:
      - file_event
      - linux
  - title: Detect VSIX Uploads with Path Traversal
    description: Detects VSIX uploads with potential path traversal attempts based on request parameters.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A Zip Slip vulnerability (CVE-2026-35454) exists in the Coder code-marketplace application, specifically in versions up to 2.4.1. The vulnerability stems from improper sanitization of zip entry names during VSIX file extraction, which allows an attacker to write files to arbitrary locations on the server. This flaw, discovered by Kandlaguduru Vamsi and detailed in GHSA-8x9r-hvwg-c55h, can be exploited by any authenticated user with upload privileges. Successful exploitation could lead to persistence via cron/init injection, SSH key injection, `ld.so.preload` hijacking, or binary overwrite. The vulnerability was patched in version 2.4.2. Defenders should upgrade to the latest version of the code-marketplace application to prevent potential exploitation.

## Attack Chain

1. An authenticated user with upload privileges logs into the code-marketplace application.
2. The attacker crafts a malicious VSIX file containing zip entries with path traversal sequences (e.g., "../../../etc/cron.d/evil").
3. The attacker uploads the malicious VSIX file through the application's extension upload functionality.
4. The `ExtractZip` function processes the uploaded VSIX file without proper sanitization of zip entry names.
5. The `filepath.Join` function constructs the output path using the unsanitized zip entry name and a base directory.
6.  Path traversal sequences like `..` are resolved by `filepath.Clean`, but the resulting path is not checked against the intended base directory, allowing it to escape.
7. The application writes the extracted file to an attacker-controlled location on the server's file system.
8. The attacker achieves persistence, privilege escalation, or arbitrary code execution by overwriting critical system files or injecting malicious code into system configurations like cron jobs or SSH authorized keys.

## Impact

Successful exploitation of this Zip Slip vulnerability allows attackers to write arbitrary files to the underlying system. An attacker can achieve persistence by injecting malicious cron jobs or modifying system initialization scripts. Privilege escalation is possible via SSH key injection or by overwriting binaries with malicious versions. The impact ranges from system compromise to data exfiltration and denial of service. While the number of victims is unknown, any organization using vulnerable versions of the Coder code-marketplace application is at risk.

## Recommendation

*   Upgrade the coder/code-marketplace application to version 2.4.2 or later to remediate CVE-2026-35454.
*   Implement file integrity monitoring on critical system directories (e.g., /etc/cron.d, /root/.ssh) using a file_event log source to detect unauthorized file modifications.
*   Deploy the Sigma rule "Detect Suspicious File Creation in Sensitive Directories" to detect potential exploitation attempts based on file creation events.
*   Enable webserver logging and deploy the provided Sigma rule "Detect VSIX Uploads with Path Traversal" to identify suspicious VSIX uploads containing path traversal sequences based on request parameters.
