---
title: Suspicious Unshare Usage for Container Escape and Privilege Escalation
slug: 2024-01-unshare-container-escape
description: The rule identifies suspicious usage of unshare to manipulate system namespaces, which can be utilized to escalate privileges or escape container security boundaries.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - container-escape
  - linux
vendors:
  - Elastic
products:
  - Elastic Defend for Containers
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://man7.org/linux/man-pages/man1/unshare.1.html
  - https://attack.mitre.org/techniques/T1543/
  - https://attack.mitre.org/techniques/T1611/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: Suspicious Unshare Usage in Container
    description: Detects suspicious usage of the unshare command within a container to manipulate namespaces for privilege escalation or container escape.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: Unshare with Network Namespace Manipulation
    description: Detects unshare usage with network namespace manipulation arguments, indicating potential attempts to isolate network interfaces.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `unshare` command in Linux is used to create new namespaces, isolating processes from the rest of the system. This isolation is crucial for containerization and security. However, attackers can exploit `unshare` to break out of containers or elevate privileges by creating namespaces that bypass security controls. This activity has been observed in containerized environments where threat actors attempt to gain unauthorized access to the host system or escalate their privileges within the container. The detection rule identifies suspicious `unshare` executions by monitoring process starts, filtering out benign parent processes, and focusing on unusual usage patterns, thus highlighting potential misuse. The rule covers activity starting from Elastic Defend for Containers version 9.3.0.

## Attack Chain

1.  A containerized process is compromised, potentially through an initial exploit or misconfiguration.
2.  The attacker executes the `unshare` command within the container.
3.  `unshare` is used to create new namespaces, isolating the attacker's process from the container's limitations.
4.  The attacker manipulates these namespaces to gain access to resources outside the container.
5.  The attacker attempts to escape the container by leveraging the newly created namespaces.
6.  Upon successful escape, the attacker gains access to the host system.
7.  The attacker escalates privileges on the host, potentially exploiting vulnerabilities or misconfigurations.
8.  The attacker achieves full control over the host system, allowing for data exfiltration, system compromise, or lateral movement.

## Impact

Successful exploitation can lead to container escape, allowing attackers to gain unauthorized access to the host system. This can result in privilege escalation, data exfiltration, and complete system compromise. The rule aims to detect and prevent such attacks by identifying suspicious usage of the `unshare` command, helping to maintain the integrity and security of containerized environments.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious `unshare` executions within containers and tune for your environment.
*   Review and whitelist legitimate uses of `unshare` by system management tools like `udevadm` and `systemd-udevd` to reduce false positives, as mentioned in the rule's description.
*   Implement additional monitoring and alerting for unusual `unshare` usage patterns to enhance detection capabilities and prevent future occurrences.
