---
title: Linux MOTD Script Persistence Technique
slug: 2026-08-linux-motd-persistence
description: Attackers can achieve persistence or privilege escalation by creating or modifying scripts in the '/etc/update-motd.d/' directory, which execute automatically upon user login.
date: "2026-08-07T15:15:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: This can be used by attackers for persistence if it contains malicious code.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1037
    technique_name: Boot or Logon Initialization Scripts
    evidence: The following analytic detects the creation of a file within the /etc/update-motd.d directory. This is used to add scripts that run with Message of the Day (MOTD) when a user logs in.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The following analytic detects the creation of a file within the /etc/update-motd.d directory.
    confidence_band: med
rules:
  - title: Detect Linux MOTD Script Addition or Modification
    description: Detects the creation or modification of files within /etc/update-motd.d/, a common persistence technique on Linux systems.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1037
      - T1547
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Deploy the Sigma rule provided in this brief.
      owner: Detection Engineering
      due: 48h
      evidence: Addresses potential persistence via MOTD scripts.
  mitigation_plan:
    - priority: short_term
      action: Restrict write access to /etc/update-motd.d/ to authorized accounts only.
      owner: IT Operations
      addresses: T1547
      evidence: Limiting access to sensitive directories reduces persistence vectors.
---

The '/etc/update-motd.d/' directory on Linux systems allows administrators to define scripts that generate the Message of the Day (MOTD), a text banner displayed to users upon successful remote login via SSH. Because these scripts are executed with the privileges of the system or the logging-in user, they represent a significant persistence vector. Attackers who gain sufficient privileges to modify files in this directory can insert malicious code that triggers during subsequent logins. This technique is particularly effective as it allows for the execution of payloads, lateral movement tools, or backdoors without requiring specialized rootkit software, making it a common choice for post-exploitation persistence. Defenders should treat any unauthorized file creation or modification in this directory as a high-fidelity indicator of a potential compromise.

## Attack Chain

1. Attacker gains initial access or a foothold on the target Linux system through an exploit or credential theft.
2. Attacker performs local enumeration to identify the user's current shell and existing system configurations.
3. Attacker identifies the '/etc/update-motd.d/' directory as a target for persistence.
4. Attacker checks write permissions on the directory or existing scripts using standard tools like 'ls -l'.
5. Attacker creates a new script or modifies an existing script within '/etc/update-motd.d/' containing malicious commands (e.g., a reverse shell).
6. Attacker ensures the malicious file has the necessary execute permissions (e.g., 'chmod +x').
7. A legitimate user (often a system administrator) logs into the server via SSH.
8. The PAM (Pluggable Authentication Modules) framework executes the scripts in '/etc/update-motd.d/', triggering the attacker's payload.

## Impact

Successful exploitation of this technique leads to persistent unauthorized access to the affected Linux system. This can be used to exfiltrate sensitive data, maintain long-term access for data theft, or provide a staging point for further lateral movement within the network. In scenarios where a root user logs in, the attacker can achieve persistent root-level execution.

## Recommendation

* Deploy the provided Sigma rule to detect file modifications within '/etc/update-motd.d/'.
* Audit all current files within '/etc/update-motd.d/' to ensure they match approved system configuration and are signed or monitored for changes.
* Enable Sysmon for Linux or equivalent EDR telemetry (Event ID 11) to monitor file system activity in system directories.
* Implement file integrity monitoring (FIM) on '/etc/update-motd.d/' to alert on any unauthorized modifications.
