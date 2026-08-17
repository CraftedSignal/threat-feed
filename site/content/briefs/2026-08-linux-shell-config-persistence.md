---
title: Monitoring Unauthorized Modifications to Unix Shell Configuration Files
slug: 2026-08-linux-shell-config-persistence
description: Detection of unauthorized modifications to shell configuration files (e.g., .bashrc, .profile) used by attackers for persistence and privilege escalation on Linux systems.
date: "2026-08-17T18:36:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - linux
  - auditd
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.004
    technique_name: 'Event Triggered Execution: Unix Shell Configuration Modification'
    evidence: Unauthorized changes to these files can be used to execute malicious commands, escalate privileges, or hide malicious activities.
    confidence_band: high
rules:
  - title: Detect Unauthorized Modification of Unix Shell Configuration
    description: Detects modifications to common Unix/Linux shell configuration files (e.g., .bashrc, .profile) using Linux Auditd logs.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable auditd logging for shell configuration paths
      owner: IT Operations
      due: 72h
      evidence: Configuration requirement for detection
  hunt_leads:
    - lead: Search for unauthorized write/append operations to /home/ directories shell profiles
      technique_id: T1546.004
      data_needed:
        - Auditd Path/Cwd events
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Analytic identifies these files as critical persistence points
  mitigation_plan:
    - priority: short_term
      action: Implement file integrity monitoring (FIM) for sensitive configuration files
      owner: Security Engineering
      addresses: T1546.004
      evidence: Prevents unauthorized modification
---

This detection focuses on unauthorized access or modifications to critical Unix shell configuration files, including but not limited to `.bashrc`, `.profile`, and files within `/etc/profile.d/`. These files are responsible for defining the user environment and executing commands upon session initialization. Adversaries frequently target these scripts to achieve persistence, execute malicious payloads automatically when a user logs in, or escalate privileges by injecting code into scripts executed by privileged accounts.

The analytic identifies this activity by monitoring Linux Auditd logs specifically for path and current working directory events that reference shell initialization scripts. Because administrators and deployment tools also interact with these files for legitimate automation, the detection logic relies on auditd's ability to provide process and user context, allowing security teams to differentiate between authorized maintenance and malicious tampering. This monitoring is essential for uncovering "living-off-the-land" techniques where legitimate system tools are repurposed for persistent access.

## Impact

Successful manipulation of shell configuration files provides attackers with a reliable, long-term foothold on compromised Linux hosts. If left undetected, this technique allows for the consistent execution of malicious code, the potential for lateral movement, and the silent exfiltration of data by capturing environment variables or intercepting user activity at every login.

## Recommendation

1. Enable and configure `auditd` to capture `PATH`, `CWD`, `SYSCALL`, `EXECVE`, and `PROCTITLE` events to provide the necessary telemetry for identifying processes modifying sensitive configuration files.
2. Implement the provided Auditd monitoring logic in your SIEM to flag modifications to files listed in the `matched_paths` regex, including all user-specific home directory shell profiles.
3. Correlate detection events with `EXECVE` or `PROCTITLE` logs to identify the specific process or user responsible for the modification.
4. Establish a baseline for authorized configuration management (e.g., Ansible, Puppet) to filter out legitimate automation activities and reduce false positives.
