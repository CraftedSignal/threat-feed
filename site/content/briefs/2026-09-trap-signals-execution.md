---
title: Abuse of POSIX Shell Trap Command for Persistence and Privilege Escalation
slug: 2026-09-trap-signals-execution
description: Adversaries leverage the POSIX shell 'trap' built-in to bind malicious payloads to interrupt signals, enabling automated execution for persistence or privilege escalation when specific signals are received.
date: "2026-09-18T19:24:25Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - privilege-escalation
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Adversaries commonly embed traps in bash, zsh, or service scripts so pressing Ctrl+C or a daemon reload silently runs a payload.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: By embedding these traps within shell startup files or service scripts, attackers can achieve persistence.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1546/005/
rules:
  - title: Detect Use of Trap Command for Signal Binding
    description: Detects the execution of the shell trap built-in with signal arguments, which can be used to execute arbitrary payloads upon receiving interrupt signals.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.005
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Search for 'trap SIG' in all initialization and service scripts.
      technique_id: T1546.005
      data_needed:
        - File content logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Search the host for other trap definitions in login and init paths.
---

Adversaries can abuse the POSIX shell 'trap' built-in command to bind arbitrary commands to interrupt signals such as SIGINT, SIGHUP, or SIGTERM. This technique enables attackers to trigger malicious payloads automatically when a process receives a specific signal, or when a user interacts with a shell (e.g., pressing Ctrl+C). By embedding these traps within shell startup files (.bashrc, .zshrc), system initialization scripts, or service unit files, attackers establish persistence or execute actions with elevated privileges. 

This method is particularly effective because the malicious code executes silently without requiring the user to invoke a specific binary, making it a subtle technique for achieving persistence or triggering privilege escalation payloads, such as modifying /etc/sudoers or deploying reverse shells. Defenders must distinguish between this malicious signal binding and legitimate administrative cleanup tasks, which also frequently utilize trap handlers to perform graceful service shutdowns.

## Impact

Successful exploitation allows attackers to maintain stealthy persistence and escalate privileges on compromised Linux and macOS systems. Impact includes unauthorized modification of system configuration files, deployment of setuid helpers for long-term access, and the establishment of persistent reverse shells. Because the trigger is signal-based, the malicious activity may occur sporadically or only when specific administrative actions are performed, complicating detection and attribution.

## Recommendation

- Deploy the provided Sigma rule to monitor for suspicious process execution involving the 'trap' command and signal-related arguments.
- Implement file integrity monitoring on shell configuration files, including .bashrc, .zshrc, /etc/profile, and /etc/profile.d, to detect unauthorized trap definitions.
- Audit systemd unit files and cron wrappers for trap commands bound to privileged operations or shell execution.
- Restrict write access to system-wide initialization scripts and service unit configurations to privileged accounts only.
- Establish alerting for modifications to /etc/sudoers and critical PAM configuration files.
