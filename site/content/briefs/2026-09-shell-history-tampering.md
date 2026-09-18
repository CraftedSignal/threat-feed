---
title: Tampering of Shell Command-Line History
slug: 2026-09-shell-history-tampering
description: Adversaries manipulate shell command-line history files and environment variables on Unix-like systems to evade detection and hinder post-compromise forensic analysis.
date: "2026-09-18T19:09:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - linux
  - macos
  - shell-history
  - persistence
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_deletion_of_bash_command_line_history.toml
  - https://attack.mitre.org/techniques/T1070/003/
rules:
  - title: Detect Shell Command-Line History Tampering
    description: Detects attempts to clear, disable, or delete shell command-line history files via process arguments.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.003
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to identify history tampering attempts
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit process arguments for history tampering
  hunt_leads:
    - lead: Search for historical process execution logs containing HISTFILE= or history -c
      technique_id: T1070.003
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers frequently use these commands to evade forensic detection
---

Adversaries frequently target command-line history files, such as .bash_history and .zsh_history, to obscure their activities during unauthorized system access. By deleting history files, truncating them, or redirecting history logging to /dev/null, attackers prevent security teams from reconstructing their actions. This behavior involves the manipulation of specific environment variables like HISTFILE and HISTFILESIZE, which govern logging persistence. Defending against this requires monitoring process execution for common utilities - such as rm, echo, truncate, unset, and export - when invoked against history files or history configuration parameters. This threat affects both Linux and macOS environments and is a standard technique used across various post-exploitation scenarios to ensure stealth.

## Attack Chain

1. Attacker gains initial access to a Linux or macOS host.
2. Attacker executes shell commands or scripts to perform reconnaissance or lateral movement.
3. Attacker identifies the target shell history file (e.g., ~/.bash_history).
4. Attacker attempts to disable future logging by setting HISTFILE to /dev/null or HISTFILESIZE to 0.
5. Attacker clears current session history by executing 'history -c'.
6. Attacker deletes or overwrites existing history files using commands like 'rm' or 'truncate -s0'.
7. Attacker continues malicious activities, knowing that subsequent commands will not be recorded in the local history files.

## Impact

Successful tampering with shell history prevents security teams from conducting accurate forensic analysis after a breach. This complicates the identification of compromised credentials, the scope of exfiltration, and the persistence mechanisms used by the attacker, effectively granting the adversary extended dwell time and making incident response significantly more difficult.

## Recommendation

Prioritize monitoring for command-line arguments that signal tampering attempts.
- Deploy the provided Sigma rules to identify attempts to manipulate shell environment variables and history files.
- Implement strict auditing (e.g., auditd) to track all modifications to sensitive shell history files located in /root, /home/*, and /Users/* directories.
- Use centralized logging to forward shell history data in real-time, which mitigates the risk of local tampering.
- Establish alerting for the execution of 'export HISTFILE=/dev/null' or 'history -c' across the environment.
