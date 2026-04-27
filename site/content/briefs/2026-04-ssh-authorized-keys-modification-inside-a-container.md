---
title: SSH Authorized Key File Modification Inside a Container
slug: 2026-04-ssh-authorized-keys-modification-inside-a-container
description: The rule detects the creation or modification of an authorized_keys file inside a container, a technique used by adversaries to maintain persistence on a victim host by adding their own public key(s) to enable unauthorized SSH access for lateral movement or privilege escalation.
date: "2026-04-02T12:00:00Z"
severities:
  - medium
tags:
  - container
  - persistence
  - lateral-movement
  - privilege-escalation
  - ssh
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1563
    technique_name: Remote Service Session Hijacking
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/persistence_ssh_authorized_keys_modification_inside_a_container.toml
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/004/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/004/
  - https://attack.mitre.org/techniques/T1563/
  - https://attack.mitre.org/techniques/T1563/001/
  - https://attack.mitre.org/tactics/TA0008/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: SSH Authorized Key File Activity Detected in Container
    description: Detects the creation or modification of SSH authorized_keys files within a container. This activity is often associated with unauthorized access and persistence.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - persistence
      - privilege_escalation
    techniques:
      - T1098.004
    data_sources:
      - file_event
      - linux
  - title: Suspicious Interactive Shell in Container Modifying SSH Keys
    description: Detects interactive shell sessions within containers that modify SSH authorized keys, which could indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - persistence
      - privilege_escalation
    techniques:
      - T1098.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection focuses on identifying malicious actors who modify SSH authorized_keys files inside containers to gain unauthorized access. SSH authorized keys are used for public key authentication, and modification of these files allows attackers to maintain persistence or move laterally within a containerized environment. The rule specifically looks for file creation and modification events of authorized_keys files within Linux-based containers. Introduced as part of the Defend for Containers…
