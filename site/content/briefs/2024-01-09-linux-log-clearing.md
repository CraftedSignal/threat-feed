---
title: Linux Log Clearing Attempts via Common Utilities
slug: 2024-01-09-linux-log-clearing
description: Adversaries attempt to clear Linux system logs using utilities like rm, rmdir, shred, and unlink to conceal malicious activity and evade detection.
date: "2024-01-09T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - defense-evasion
  - log-clearing
  - linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
rules:
  - title: Detect Log Clearing via rm Utility
    description: Detects log clearing attempts using the 'rm' command targeting common log directories.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1070.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Log Clearing via shred Utility
    description: Detects log clearing attempts using the 'shred' command to overwrite log files.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1070.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Log Clearing via unlink Utility
    description: Detects log clearing attempts using the 'unlink' command to remove log files.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1070.002
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Attackers often remove or modify system logs to hide their actions and hinder forensic investigations. This activity involves the use of common Linux utilities to delete or overwrite log files, making it difficult to trace the attacker's entry point, lateral movement, and actions performed on the system. Log clearing is a common post-exploitation technique used by a wide range of threat actors across various campaigns. This brief focuses on detecting the usage of common utilities like `rm`…
