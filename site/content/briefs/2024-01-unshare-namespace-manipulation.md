---
title: Suspicious Unshare Usage for Namespace Manipulation
slug: 2024-01-unshare-namespace-manipulation
description: The `unshare` command is used to create new namespaces in Linux, which can be exploited to break out of containers or elevate privileges by creating namespaces that bypass security controls.
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
  - SentinelOne
products:
  - Elastic Defend
  - Auditbeat
  - Elastic Endgame
  - SentinelOne Cloud Funnel
affected_os:
  - Linux
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
  - https://www.crowdstrike.com/blog/cve-2022-0185-kubernetes-container-escape-using-linux-kernel-exploit/
rules:
  - title: Namespace Manipulation Using Unshare
    description: Detects suspicious usage of the unshare command to manipulate system namespaces, potentially leading to privilege escalation or container escape.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1543
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: Unusual Unshare with Mount Namespace
    description: Detects unshare command usage with mount namespace creation, excluding known false positives.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1543
      - T1611
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `unshare` command in Linux is a utility used to create new namespaces, providing isolation for processes. While crucial for containerization and security, attackers can misuse `unshare` to escape container boundaries or escalate privileges by manipulating system namespaces. This occurs by creating namespaces that bypass established security controls. This activity is often observed when threat actors attempt to gain unauthorized access to host resources or elevate their privileges within a compromised system. The focus of this detection is on identifying unusual `unshare` executions that deviate from legitimate system management activities.

## Attack Chain

1.  An attacker gains initial access to a Linux system, potentially through exploiting a vulnerability in a containerized application.
2.  The attacker executes the `unshare` command.
3.  `unshare` creates new namespaces, isolating the attacker's process from the rest of the system.
4.  The attacker attempts to mount sensitive directories from the host system into the new namespace.
5.  Using the newly gained access, the attacker attempts to modify system files, such as `/etc/passwd` or `/etc/shadow`, to create new privileged accounts.
6.  The attacker leverages the elevated privileges to install persistent backdoors or malware on the host system.
7.  The attacker attempts to move laterally to other systems on the network.
8.  The attacker achieves their final objective, such as data exfiltration or system disruption.

## Impact

Successful exploitation via `unshare` can lead to privilege escalation, container escape, and unauthorized access to sensitive resources on the host system. The impact includes potential data breaches, system compromise, and lateral movement within the network. While the number of victims is unknown, the widespread use of containerization technologies makes this a significant threat, particularly for organizations relying on Linux-based container environments and cloud infrastructures.

## Recommendation

*   Deploy the Sigma rule `Namespace Manipulation Using Unshare` to your SIEM to detect suspicious `unshare` command executions and tune for your environment.
*   Enable Auditbeat or Elastic Defend to collect the necessary process execution data to trigger the provided Sigma rule, as outlined in the rule's `setup` section.
*   Review and tune the provided Sigma rule's exclusion list based on your environment's legitimate use cases for `unshare`, as described in the "False positive analysis" section.
*   Implement additional monitoring and alerting for unusual `unshare` usage patterns to enhance detection capabilities and prevent future occurrences as recommended in the "Response and remediation" section.
