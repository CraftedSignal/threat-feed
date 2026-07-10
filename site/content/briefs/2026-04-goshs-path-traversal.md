---
title: goshs SimpleHTTPServer SFTP Rename Path Traversal Vulnerability (CVE-2026-40188)
slug: 2026-04-goshs-path-traversal
description: The goshs SimpleHTTPServer, from version 1.0.7 to before 2.0.0-beta.4, is vulnerable to path traversal (CVE-2026-40188) due to insufficient sanitization of the destination path in the SFTP rename command, potentially allowing attackers with low privileges to write files outside the intended root directory.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - sftp
  - cve-2026-40188
vendors:
  - goshs
products:
  - goshs
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-40188
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40188
  - https://github.com/patrickhener/goshs/commit/141c188ce270ffbec087844a50e5e695b7da7744
  - https://github.com/patrickhener/goshs/releases/tag/v2.0.0-beta.4
  - https://github.com/patrickhener/goshs/security/advisories/GHSA-2943-crp8-38xx
rules:
  - title: Detect SFTP Rename with Path Traversal
    description: Detects SFTP rename commands with destination paths containing path traversal sequences, indicating potential exploitation of CVE-2026-40188 in goshs.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - firewall
      - linux
  - title: Detect Attempts to Write Outside SFTP Root Directory
    description: Detects attempts to write files outside the SFTP root directory by monitoring file creation events with paths containing path traversal sequences.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

goshs is a SimpleHTTPServer written in Go. Versions 1.0.7 to before 2.0.0-beta.4 are vulnerable to a path traversal issue (CVE-2026-40188) within the SFTP rename command. This vulnerability arises because the application only sanitizes the source path during a rename operation, neglecting to sanitize the destination path. This oversight allows authenticated attackers with low privileges to manipulate file paths and potentially write files outside the designated SFTP root directory, leading to unauthorized file creation or modification. The vulnerability is resolved in version 2.0.0-beta.4. This vulnerability poses a risk to systems using vulnerable versions of goshs for file sharing.

## Attack Chain

1.  Attacker gains low-privilege access to the goshs server via SSH or other means.
2.  Attacker establishes an SFTP session with the vulnerable goshs server.
3.  Attacker identifies a file or directory within their authorized SFTP root.
4.  Attacker crafts an SFTP rename command where the source is a legitimate file within their SFTP root.
5.  The attacker crafts the destination path of the rename command to include path traversal sequences (e.g., "../") to move outside of the intended root directory.
6.  The vulnerable goshs server executes the rename command using the attacker-controlled destination path without proper sanitization.
7.  The attacker successfully creates or overwrites files in unauthorized locations on the server's file system.
8.  The attacker may leverage the ability to write arbitrary files to achieve persistence by modifying system configuration files.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass intended access restrictions and potentially overwrite critical system files, leading to code execution or denial-of-service. The impact is high due to the potential for privilege escalation and system compromise. While the exact number of vulnerable installations is unknown, any organization using goshs versions 1.0.7 to before 2.0.0-beta.4 are potentially at risk. Successful exploitation can lead to unauthorized data modification, or system instability.

## Recommendation

*   Upgrade goshs to version 2.0.0-beta.4 or later to remediate CVE-2026-40188 as mentioned in the overview.
*   Monitor SFTP logs for rename operations containing path traversal sequences like "../" in the destination path. (Generic Recommendation)
*   Implement file integrity monitoring (FIM) on critical system directories to detect unauthorized file modifications resulting from successful exploitation. (Generic Recommendation)
