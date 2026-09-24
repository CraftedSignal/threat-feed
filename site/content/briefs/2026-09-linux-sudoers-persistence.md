---
title: Linux Sudoers File Modification for Persistence and Privilege Escalation
slug: 2026-09-linux-sudoers-persistence
description: Adversaries manipulate the /etc/sudoers file or /etc/sudoers.d/ directory to establish persistence and gain unauthorized elevated privileges on Linux systems.
date: "2026-09-24T06:08:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - linux
  - security-configuration
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Adversaries may alter sudoers configuration to execute commands with elevated privileges without supplying a password.
    confidence_band: high
rules:
  - title: Detect Modification of Sudoers Configuration Files
    description: Detects the creation or modification of the main /etc/sudoers file or files within the /etc/sudoers.d/ directory.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1548.003
    data_sources:
      - file_event
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor sudoers file changes
      owner: Detection Engineering
      due: 48h
      evidence: Source provides logic for detecting sudoers persistence
  hunt_leads:
    - lead: Search for existing NOPASSWD entries in all /etc/sudoers.d/ files
      technique_id: T1548.003
      data_needed:
        - File content snapshots
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Attacker goal is passwordless sudo access
  mitigation_plan:
    - priority: medium
      action: Restrict write access to /etc/sudoers and /etc/sudoers.d/ to root only
      owner: IT Operations
      addresses: T1548.003
      evidence: Sudoers file security best practices
---

Adversaries targeting Linux environments often seek to gain and maintain elevated privileges by modifying the sudoers configuration files. The sudoers file, located at /etc/sudoers, and the directory /etc/sudoers.d/ control user access to the sudo command. By injecting custom configuration lines, an attacker can grant their user account passwordless root execution, essentially providing a persistent backdoor with administrative access. This technique is observed in various malware kits, such as the TripleCross rootkit, which utilizes modification of these files to ensure persistence. Defenders must distinguish between authorized changes made by configuration management tools (like Ansible or Chef) or system package updates and unauthorized modifications that indicate malicious intent.

## Attack Chain

1. Attacker gains initial access to a Linux system via an exploit or stolen credentials.
2. Attacker enumerates current user privileges and sudoers configuration files.
3. Attacker identifies the target sudoers file or a sub-file within /etc/sudoers.d/ for modification.
4. Attacker writes malicious configuration strings (e.g., "user ALL=(ALL) NOPASSWD: ALL") to the target file.
5. Attacker leverages file integrity monitoring or system tools to persist changes.
6. Attacker executes commands using sudo without needing to provide a password.
7. Final objective is achieved, such as long-term persistence or data exfiltration as root.

## Impact

Successful modification of sudoers files results in complete system compromise, allowing an attacker to maintain persistent, passwordless administrative access. This enables full control over the host, potential lateral movement, and unmonitored exfiltration of sensitive data.

## Recommendation

* Deploy the provided Sigma rule to monitor file modifications to /etc/sudoers and the /etc/sudoers.d/ directory.
* Establish a baseline for authorized configuration management tools (e.g., SaltStack, Puppet, Ansible) that legitimately modify these files to reduce false positives.
* Audit existing sudoers configuration files for unauthorized "NOPASSWD" directives or unfamiliar user entries.
* Enable file integrity monitoring (FIM) on /etc/sudoers and /etc/sudoers.d/ to alert on any changes in real-time.
