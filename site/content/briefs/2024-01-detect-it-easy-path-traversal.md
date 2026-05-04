---
title: Detect-It-Easy Path Traversal Vulnerability (CVE-2026-43616)
slug: 2024-01-detect-it-easy-path-traversal
description: Detect-It-Easy versions prior to 3.21 are vulnerable to path traversal, allowing attackers to write arbitrary files to the filesystem and potentially achieve code execution by crafting malicious archive entries.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - vulnerability
  - archive-extraction
products:
  - Detect-It-Easy (DIE) < 3.21
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-43616
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43616
rules:
  - title: Detect-It-Easy Suspicious Archive Extraction
    description: Detects attempts to use Detect-It-Easy to extract archives with path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Detect-It-Easy Suspicious Archive Extraction (Linux)
    description: Detects attempts to use Detect-It-Easy to extract archives with path traversal sequences on Linux.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Detect-It-Easy (DIE) is a program used to detect file types, unpackers, compilers, and crypto information. Versions prior to 3.21 are susceptible to a path traversal vulnerability (CVE-2026-43616). This vulnerability enables a malicious actor to write arbitrary files to the underlying filesystem by crafting archive entries with relative traversal sequences (e.g., "../../") or absolute paths. This can be exploited by attackers by overwriting sensitive system files or user startup scripts, thus leading to persistent code execution. The vulnerability stems from insufficient path normalization during archive extraction.

## Attack Chain

1.  The attacker crafts a malicious archive (e.g., ZIP, TAR) containing files with path traversal sequences in their filenames or absolute paths.
2.  The user executes Detect-It-Easy and loads the malicious archive for scanning.
3.  Detect-It-Easy attempts to extract the files from the archive.
4.  Due to insufficient path normalization, the application does not properly sanitize the file paths.
5.  The application writes files outside the intended extraction directory.
6.  The attacker overwrites a user startup script (e.g., .bashrc, .profile) with malicious code.
7.  The user logs in or starts a new shell session.
8.  The malicious code in the startup script executes, granting the attacker persistent access or executing arbitrary commands.

## Impact

Successful exploitation of this vulnerability allows an attacker to write arbitrary files to the filesystem with the privileges of the user running Detect-It-Easy. This could lead to complete system compromise through persistent code execution. The impact includes potential data theft, malware installation, or denial of service. While the number of victims is not specified, any user running a vulnerable version of Detect-It-Easy is at risk.

## Recommendation

*   Upgrade Detect-It-Easy to version 3.21 or later to patch CVE-2026-43616.
*   Implement the Sigma rule "Detect-It-Easy Suspicious Archive Extraction" to identify potential exploitation attempts by detecting the execution of Detect-It-Easy with archive files containing path traversal sequences.
*   Monitor file creation events for suspicious file writes outside of expected directories, particularly in user startup script locations, to detect potential exploitation based on file_event logsource.
