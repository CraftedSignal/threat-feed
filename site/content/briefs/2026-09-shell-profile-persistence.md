---
title: Detecting Persistence via Unix Shell Profile Modification
slug: 2026-09-shell-profile-persistence
description: Adversaries maintain persistence on Linux and macOS systems by modifying shell configuration files to execute malicious payloads automatically upon user login or shell session initialization.
date: "2026-09-18T19:22:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Adversaries may abuse this to establish persistence by executing malicious content triggered by a user’s shell.
    confidence_band: high
rules:
  - title: Bash and Zsh Shell Profile Modification
    description: Detects unauthorized modifications to shell profile files which can be used to achieve persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.004
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule to monitor changes to shell profiles.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Identify all modifications to dotfiles in home directories within the last 30 days.
      technique_id: T1546.004
      data_needed:
        - File integrity logs
      priority: medium
      confidence: medium
      disposition: hunt_now
---

Adversaries frequently establish persistence on Unix-like operating systems (Linux and macOS) by tampering with shell initialization files such as .bash_profile, .bashrc, .profile, .zshenv, or .zshrc. These files are inherently designed to execute commands within the user's context whenever a shell session is opened or a user logs in. By appending malicious code or backdoors to these scripts, attackers ensure that their code is automatically executed without requiring explicit user interaction.

This technique is a common post-exploitation step used to maintain long-term access after an initial compromise. Defenders must monitor file system changes to these specific configuration files to identify unauthorized modifications. Because shell profiles are frequently updated by legitimate administrative tools, installers, and system management scripts, detection logic requires careful tuning to exclude known benign processes and paths while alerting on suspicious, non-interactive, or unusual executables that modify these files.

## Attack Chain

1. An attacker gains initial access to a Linux or macOS endpoint via an exploit or stolen credentials.
2. The attacker identifies the current user's shell environment (e.g., checking /etc/passwd or $SHELL environment variable).
3. The attacker locates shell configuration files in the user home directory (/home/* or /Users/*).
4. The attacker writes malicious commands (e.g., reverse shell connections or malware droppers) into the target shell profile file using non-standard utilities.
5. The attacker waits for the user to log in or open a new terminal window.
6. The system executes the contents of the modified shell profile automatically.
7. The attacker's malicious payload executes in the user's context, providing persistent access.

## Impact

Successful exploitation allows an attacker to maintain persistent, long-term access to a compromised system. This can lead to continuous data exfiltration, lateral movement within the network, and the deployment of additional malicious tools. The scope includes any Linux or macOS machine where user shell profiles can be modified by unauthorized processes.

## Recommendation

1. Deploy file integrity monitoring (FIM) or specialized endpoint detection rules to alert on modifications to critical shell profile files.
2. Implement the provided Sigma rule to identify unauthorized modifications and tune it based on the specific administrative and deployment tooling in your environment.
3. Regularly audit shell profile files on critical systems to ensure that they contain only expected configuration commands.
4. Restrict file system write permissions for shell profile files to the minimum required users and processes.
5. Investigate processes that modify these files if they do not match established administrative baselines.
