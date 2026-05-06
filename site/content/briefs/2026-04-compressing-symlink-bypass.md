---
title: compressing npm Package Symlink Bypass Vulnerability
slug: 2026-04-compressing-symlink-bypass
description: A vulnerability in the `compressing` npm package (<=v2.1.0) allows for arbitrary file overwrite via symlink path traversal, bypassing a previous patch for CVE-2026-24884.
date: "2026-04-18T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - npm
  - supply-chain
  - symlink
  - directory-traversal
  - privilege-escalation
  - arbitrary-file-overwrite
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-24884
    cvss: 8.4
    epss: 8e-05
references:
  - https://github.com/advisories/GHSA-4c3q-x735-j3r5
iocs:
  - type: url
    value: https://github.com/sachinpatilpsp/compressing_poc_test.git
    context: Proof-of-concept exploit code
ioc_counts:
  url: 1
rules:
  - title: Detect File Writes Following Symlinks
    description: Detects file writes to unexpected locations that are targeted via symlinks.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.001
    data_sources:
      - file_event
      - linux
  - title: Detect Node.js Processes Loading Compressing Module with Network Connections
    description: Detects network connections initiated by Node.js processes that have loaded the `compressing` module, potentially indicating post-exploitation activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
  - title: Detect suspicious symlink creation
    description: Detects the creation of suspicious symlinks, which are often used in path traversal attacks.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.001
    data_sources:
      - file_event
      - linux
rules_count: 3
---

The `compressing` npm package (v2.1.0 and earlier) contains a critical vulnerability that permits arbitrary file overwrites due to a symlink path traversal bypass. This bypass affects the patch for CVE-2026-24884. The vulnerability arises from an incomplete validation in the `isPathWithinParent` utility, where path string checks are performed without verifying the filesystem state, specifically symbolic links. By cloning a malicious repository containing a pre-existing symbolic link, a victim unknowingly plants a "poisoned path" on their system. The attacker can then craft a malicious archive that, when extracted by the vulnerable library, follows the symlink and overwrites arbitrary files. The ease of exploitation via `git clone` makes this vulnerability particularly dangerous.

## Attack Chain

1.  Attacker creates a malicious Git repository containing a symbolic link (e.g., `config_file`) pointing to a sensitive target file or directory (e.g., `/tmp/fake_root/etc/passwd`).
2.  Attacker generates a malicious payload (e.g., `payload.tar`) containing a file with the same name as the symbolic link (e.g., `config_file`) and uploads both to their Git repository.
3.  Victim clones the attacker's Git repository using `git clone`. This action automatically restores the symbolic link on the victim's system.
4.  Victim runs an application that utilizes the vulnerable `compressing` library to extract the `payload.tar` archive.
5.  The `compressing` library's `isPathWithinParent` function resolves the path to the file being extracted. Due to lack of `lstat` checks, the symbolic link is not detected.
6.  The `fs.writeFile` function follows the symlink, writing the contents of the file from `payload.tar` to the targeted sensitive file (e.g., `/tmp/fake_root/etc/passwd`).
7.  Arbitrary file overwrite occurs, potentially leading to privilege escalation or code execution.
8.  Attacker achieves persistent access or control by overwriting critical system files.

## Impact

Successful exploitation allows attackers to overwrite arbitrary files on the victim's system, potentially leading to privilege escalation by modifying sensitive system files such as `/etc/passwd`. Remote Code Execution (RCE) can be achieved by overwriting executable binaries or startup scripts. Data corruption can also occur through the modification of application data or database files. This vulnerability impacts developers and organizations using the `compressing` library up to version v2.1.0 when extracting untrusted archives.

## Recommendation

*   Upgrade the `compressing` npm package to a patched version that includes proper symlink handling. This is the primary remediation.
*   Inspect Git repositories for suspicious symbolic links before cloning. Use `git ls-tree -r <commit-ish> | grep 120000` to search for symlinks in a repository.
*   Implement runtime monitoring for file writes to unexpected locations based on the `compressing` library's activity. Create a detection rule based on `process_creation` and `file_event` to detect writes to sensitive directories such as `/etc` by processes spawned by Node.js that also load the vulnerable `compressing` module.
*   Monitor network connections originating from processes related to the `compressing` library after file extraction. Create a Sigma rule based on `network_connection` and `process_creation` to detect unusual outbound connections after archive extraction.
