---
title: Detection of Privilege Escalation via Unauthorized Sudoers Modification
slug: 2026-09-sudoers-modification
description: Adversaries may attempt to gain elevated privileges on Unix-like systems by using the echo command to inject NOPASSWD directives into the sudoers file, allowing passwordless execution of commands as root.
date: "2026-09-18T19:22:59Z"
lastmod: "2026-09-19T13:18:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - defense-evasion
  - linux
  - macos
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Adversaries can take advantage of these configurations to execute commands as other users or spawn processes with higher privileges.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Adversaries may exploit this by modifying the file to allow unauthorized privilege escalation, often using the NOPASSWD directive to bypass password prompts.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/privilege_escalation_echo_nopasswd_sudoers.toml
rules:
  - title: Detect Potential Privilege Escalation via Sudoers Modification
    description: Detects the use of echo to append NOPASSWD directives to sudoers configuration files, a common technique for privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for echo-based modifications of sudoers files.
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief content
  hunt_leads:
    - lead: Search command history for echo commands redirecting to /etc/sudoers or /etc/sudoers.d/
      technique_id: T1548.003
      data_needed:
        - Process command line arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document identifies this as an indicator of sudoers modification
  mitigation_plan:
    - priority: short_term
      action: Restrict write access to /etc/sudoers and /etc/sudoers.d/ to root only.
      owner: IT Operations
      addresses: T1548.003
      evidence: Best practice for sudoers file management
updates:
  - at: "2026-09-19T13:18:12Z"
    level: L1
    summary: OS linux; OS macos
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/privilege_escalation_echo_nopasswd_sudoers.toml
---

Adversaries targeting Linux and macOS environments frequently attempt to achieve persistent privilege escalation by manipulating system configuration files. A common technique involves modifying the /etc/sudoers file to grant specific users or groups passwordless sudo access. By leveraging the echo command, an attacker can append a line containing the NOPASSWD: ALL directive to the sudoers file or a file within the sudoers.d directory. This configuration change effectively bypasses authentication requirements for elevated operations, granting the attacker persistent root-level command execution capabilities. Defenders should monitor for suspicious execution patterns involving the echo utility directed toward sensitive system configuration files.

## Attack Chain

1. Attacker gains initial user-level access on a Linux or macOS system.
2. Attacker identifies a target user account or group for privilege escalation.
3. Attacker uses the echo command to craft a line containing the NOPASSWD: ALL configuration directive.
4. Attacker redirects or appends the output of the echo command into the /etc/sudoers file or a file located in /etc/sudoers.d/.
5. The system configuration is updated, granting the specified user unrestricted, passwordless sudo privileges.
6. Attacker executes a command via sudo to confirm the bypass of authentication prompts.
7. Attacker proceeds to perform further post-exploitation activities, such as exfiltration or lateral movement, with elevated permissions.

## Impact

Successful exploitation allows unauthorized users to execute commands with root privileges without providing a password. This enables complete system compromise, persistent backdoor creation, and potential lateral movement across the internal network.

## Recommendation

Deploy the Sigma rule provided in this brief to detect suspicious sudoers modifications. Audit current /etc/sudoers and /etc/sudoers.d/ configurations to ensure only authorized users have elevated access. Implement rigorous logging of modifications to critical system files using tools like auditd or file integrity monitoring (FIM) solutions.
