---
title: SSH Authorized Key File Modification Inside a Container
slug: 2026-04-ssh-authorized-keys-modification-inside-a-container
description: The rule detects the creation or modification of an authorized_keys file inside a container, a technique used by adversaries to maintain persistence on a victim host by adding their own public key(s) to enable unauthorized SSH access for lateral movement or privilege escalation.
date: "2026-04-02T12:00:00Z"
type: coverage
types:
  - coverage
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

This detection focuses on identifying malicious actors who modify SSH authorized_keys files inside containers to gain unauthorized access. SSH authorized keys are used for public key authentication, and modification of these files allows attackers to maintain persistence or move laterally within a containerized environment. The rule specifically looks for file creation and modification events of authorized_keys files within Linux-based containers. Introduced as part of the Defend for Containers integration in Elastic Stack version 9.3.0, this detection is crucial because unauthorized SSH access can lead to significant compromise within cloud environments and containerized workloads. Defenders need to be aware of unexpected SSH key modifications as indicators of compromise inside containerized environments.

## Attack Chain

1.  An attacker gains initial access to a container, possibly through a software vulnerability or misconfiguration.
2.  The attacker executes commands within the container to locate the SSH authorized_keys file (typically located at `/home/<user>/.ssh/authorized_keys` or `/root/.ssh/authorized_keys`).
3.  The attacker modifies the authorized_keys file, adding their own SSH public key to the file using commands like `echo "ssh-rsa AAAAB3Nz..." >> /root/.ssh/authorized_keys`.
4.  The attacker uses the newly added SSH key to authenticate and log into the container without needing a password.
5.  The attacker uses the SSH session to execute further commands, potentially escalating privileges or moving laterally to other containers or systems.
6.  The attacker maintains persistence by ensuring their SSH key remains in the authorized_keys file, allowing them to re-access the container at any time.

## Impact

Successful modification of the authorized_keys file enables persistent, unauthorized SSH access to the compromised container. This can lead to lateral movement within the container environment, privilege escalation, data exfiltration, or further attacks on other systems. The rule aims to detect these modifications early, preventing significant damage. While the number of specific victims isn't stated, a successful attack targeting containers can affect critical cloud infrastructure and applications.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect unauthorized modifications of SSH authorized_keys files within containers (rule: `SSH Authorized Key File Activity`).
*   Enable `Elastic Defend for Containers` integration (minimum version 9.3.0) to provide the necessary file event data for the Sigma rule to function correctly.
*   Investigate any alerts generated by the Sigma rule, focusing on the process and user context of the file modifications, as outlined in the rule's description (rule: `SSH Authorized Key File Activity`).
*   Implement stricter access controls and monitoring on SSH usage within containers to prevent similar incidents in the future, as recommended in the incident response section.
*   Create exceptions for known update processes or deployment scripts that regularly alter these files to reduce false positives, as suggested in the false positive analysis.
