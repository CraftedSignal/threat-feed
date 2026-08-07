---
title: Detection of Unauthorized Shell History File Access on Linux
slug: 2026-08-linux-shell-history-access
description: Detection of malicious actors accessing sensitive shell history files using common command-line utilities to harvest credentials or reconnaissance data on compromised Linux hosts.
date: "2026-08-07T15:16:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - linux
  - post-exploitation
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A malicious actor who gains access to a user's shell history file can potentially obtain sensitive information and use it to compromise the user's system and data.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/linux_shell_history_access_via_command_line_utility.yml
rules:
  - title: Detect Linux Shell History Access Via Command Line Utility
    description: Detects unauthorized attempts to read shell history files using common command-line utilities
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to production SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation for linux_shell_history_access_via_command_line_utility
  hunt_leads:
    - lead: Search for historical process execution logs involving common file readers accessing hidden history files
      technique_id: T1552.003
      data_needed:
        - Process creation events with command line arguments
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source analytic defines this as a key detection area
---

This threat brief focuses on the post-exploitation technique of reading Linux shell history files (such as .bash_history, .zsh_history, and .fish_history) to gather sensitive information. Threat actors frequently target these files to recover plain-text credentials, configuration secrets, or to perform reconnaissance on system administration patterns. Access is typically achieved using standard system utilities like 'cat', 'tail', 'less', or text editors like 'vi' and 'vim'. Because these files are log-like, they are a high-value target for attackers attempting to pivot from initial access to privilege escalation or persistence. Defenders should monitor for process executions that attempt to read these specific history files to identify unauthorized user or service account activity.

## Attack Chain

1. Attacker gains initial access to a Linux host (via SSH, web vulnerability, or phishing).
2. Attacker performs local enumeration of the current user's home directory.
3. Attacker identifies the existence of shell history files (.bash_history, .zhistory, etc.).
4. Attacker uses native binaries like 'cat' or 'less' to output the file contents to the terminal.
5. Attacker captures the output for offline analysis or uses grep/strings to search for keywords (e.g., password).
6. Attacker leverages discovered credentials to escalate privileges or move laterally to other systems.

## Impact

Successful extraction of shell history files leads to the compromise of credentials and sensitive configuration data, potentially resulting in full system takeover or further propagation of the attack across the environment. This technique is observed across all Linux-based server environments and is frequently associated with post-exploitation phases where an attacker seeks to deepen their presence.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for unauthorized access to history files.
Filter the detection logic for known administrative service accounts and approved automation scripts to reduce false positives.
Ensure Sysmon for Linux or equivalent EDR telemetry is configured to capture full command-line arguments and parent process information.
