---
title: Detection of Hidden File and Directory Creation on Linux
slug: 2026-10-linux-hidden-file-evasion
description: Adversaries utilize hidden files and directories, prefixed with a dot, within world-writable Linux directories to conceal malicious artifacts and establish persistence.
date: "2026-10-08T19:36:08Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - persistence
  - linux
  - endpoint-security
affected_os:
  - Linux
rules:
  - title: Creation of Hidden Files and Directories via CommandLine
    description: Detects processes creating hidden files or directories (prefixed with a dot) within common world-writable Linux directories.
    platform: sigma
    severity: medium
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Adversaries targeting Linux systems frequently leverage the native file system behavior where any file or directory prefixed with a period (.) is automatically hidden from standard listing commands. By creating these hidden artifacts within world-writable directories such as /tmp, /var/tmp, or /dev/shm, attackers can effectively conceal malicious scripts, payloads, or persistence mechanisms from casual administrative observation. This technique is a common component of defense evasion and persistence strategies. Defenders should monitor for processes that create these hidden entries, particularly when initiated by utilities typically used for file management, downloads, or script execution. While many system processes may legitimately create temporary hidden files, identifying anomalous usage of these patterns remains a critical component of host-based monitoring.

## Attack Chain

1. Attacker gains initial access to a Linux system via an unprivileged or compromised service account.
2. Attacker identifies a world-writable directory (e.g., /tmp) to store secondary tools or payloads.
3. Attacker uses a common utility (e.g., wget, curl, or tar) to download or extract a malicious file.
4. Attacker renames the file or creates it directly with a leading dot to ensure it remains hidden from ls commands.
5. Attacker modifies permissions or adds a cron job referencing the hidden file to ensure execution or persistence.
6. The hidden file persists across reboots or administrative sessions, serving as a staging area or C2 beacon.

## Impact

Successful exploitation allows attackers to maintain stealthy persistence and hide indicators of compromise on compromised Linux hosts. This can lead to prolonged unauthorized access, data exfiltration, or further lateral movement within the network. If undetected, these hidden artifacts can exist indefinitely in temporary storage areas, facilitating long-term system compromise.

## Recommendation

Prioritize monitoring for the creation of hidden files in common writable directories to detect potential persistence and defense evasion.
- Deploy the provided Sigma rules to your SIEM to monitor process execution in /tmp, /var/tmp, and /dev/shm.
- Investigate any hidden files detected in these directories, specifically focusing on the parent process lineage and user context.
- Review and baseline common system maintenance or development scripts that legitimately use hidden temporary files to reduce alert volume.
- Ensure endpoint telemetry (e.g., Elastic Defend or equivalent EDR) is capturing process creation events with full command-line arguments.
