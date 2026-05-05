---
title: changedetection.io Arbitrary Local File Read via Crafted Backup Restore
slug: 2024-01-03-changedetectionio-file-read
description: changedetection.io is vulnerable to arbitrary local file read due to insufficient validation of snapshot paths restored from backup files, allowing attackers to read sensitive files by crafting a malicious backup archive containing a manipulated `history.txt` file.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - arbitrary-file-read
  - vulnerability
  - changedetection.io
vendors:
  - dgtlmoon
products:
  - changedetection.io (<= 0.54.10)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1598
    technique_name: Phishing for Information
references:
  - https://github.com/advisories/GHSA-8757-69j2-hx56
rules:
  - title: Detect changedetection.io Arbitrary File Read Attempt
    description: Detects attempts to read sensitive files via crafted history.txt files in changedetection.io backups.
    platform: sigma
    severity: critical
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect history.txt file modification
    description: Detects modification to the history.txt file, which could indicate an attempt to exploit the vulnerability.
    platform: sigma
    severity: medium
    techniques:
      - T1078
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in changedetection.io versions 0.54.10 and earlier that allows for arbitrary local file read. This flaw stems from the application's trust of attacker-controlled snapshot paths when restoring from backup files. By crafting a malicious backup ZIP archive, an attacker can manipulate the `history.txt` file within the archive to include a path to a sensitive local file accessible to the application process. Upon restoring the crafted backup, the application reads and displays the contents of the targeted file through the Preview UI or the watch history API, effectively bypassing intended access controls. This vulnerability, identified as CVE-2026-43891, poses a significant risk to deployments where the application has access to sensitive system files, secrets, or configuration data.

## Attack Chain

1. The attacker creates a normal watch in the changedetection.io UI to generate a valid history entry.
2. The attacker creates a backup archive using the application's built-in backup functionality.
3. The attacker extracts the backup archive and locates the watch UUID directory containing the `watch.json` file.
4. The attacker modifies the `history.txt` file within the watch UUID directory, replacing the latest history entry with a path to a sensitive local file (e.g., `/etc/passwd`).
5. The attacker repacks the backup archive, ensuring that the UUID directories are located at the root of the ZIP archive.
6. The attacker uses the restore functionality within the changedetection.io UI to restore the modified backup archive, replacing existing watches.
7. After the restore process completes, the attacker accesses the "Preview" function for the restored watch.
8. The application reads the attacker-controlled path from `history.txt` and displays the contents of the referenced local file in the Preview UI.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary local files accessible to the changedetection.io application process. This can lead to the disclosure of sensitive information such as system files (e.g., `/etc/passwd`), application configuration files, API tokens, database credentials, and other secrets. The impact is particularly severe in Docker or host-mounted environments where secrets and configuration files are explicitly readable by the service. This vulnerability can lead to complete compromise of the application and potentially the underlying system, allowing an attacker to gain unauthorized access to sensitive data and potentially escalate their privileges.

## Recommendation

- Upgrade to a version of changedetection.io later than 0.54.10 to patch CVE-2026-43891.
- Deploy the Sigma rule "Detect changedetection.io Arbitrary File Read Attempt" to identify attempts to access sensitive files via the history.txt file.
- Implement strict file access controls to limit the application's access to only the necessary files and directories.
- As described in the advisory, normalize every history entry to `os.path.basename(v)` in the `Watch.py` file.
