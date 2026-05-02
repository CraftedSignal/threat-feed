---
title: Potential Chroot Container Escape via Mount
slug: 2024-01-chroot-container-escape
description: The rule detects a potential chroot container escape via mount, which involves a user within a container mounting the host's root file system and using chroot to escape the containerized environment, indicating a privilege escalation attempt.
date: "2026-05-02T12:45:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container-escape
  - privilege-escalation
  - linux
vendors:
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Elastic Defend
  - sentinel_one_cloud_funnel
  - crowdstrike.fdr
affected_os:
  - Linux
references:
  - https://book.hacktricks.xyz/v/portugues-ht/linux-hardening/privilege-escalation/escaping-from-limited-bash
  - https://attack.mitre.org/techniques/T1611/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: Potential Chroot Container Escape via Mount
    description: Detects the execution of a file system mount followed by a chroot execution, which may indicate a container escape attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Mount Activity in Container
    description: Detects mount commands executed within a container context, potentially indicating attempts to access the host filesystem.
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

This detection rule monitors for a specific sequence of commands on Linux systems that could indicate an attempt to escape a containerized environment. The attack involves first mounting a file system, typically targeting the host's root file system, and then using the `chroot` command to change the root directory. This combination, if successful, allows an attacker inside a container to gain unauthorized access to the host system. The rule is designed to identify this uncommon behavior pattern, which is a strong indicator of malicious activity. The rule is applicable to environments utilizing Elastic Defend, SentinelOne Cloud Funnel, and Crowdstrike FDR. The detection looks for this sequence occurring within a 5-minute timeframe.

## Attack Chain

1. An attacker gains initial access to a container, possibly through exploiting a vulnerability or misconfiguration in the application running within the container.
2. The attacker attempts to mount the host's root filesystem within the container using the `mount` command, often targeting `/dev/sd*` devices. This requires sufficient privileges within the container, or the exploitation of a container escape vulnerability to gain such privileges.
3. The `mount` command is executed with arguments specifying the device to mount and the mount point within the container's file system.
4. The attacker then executes the `chroot` command, changing the root directory of the current process to the mounted host's root filesystem.
5. After successfully executing `chroot`, the attacker's perspective shifts to the host's file system, allowing them to access and modify sensitive files and configurations.
6. The attacker uses their newly acquired access to install backdoors, create new user accounts with elevated privileges, or modify system configurations to establish persistence.
7. The attacker may attempt to move laterally to other containers or systems within the network, leveraging their compromised position on the host.
8. The final objective is to gain complete control over the host system and potentially the entire infrastructure, leading to data exfiltration, system disruption, or other malicious activities.

## Impact

A successful container escape can have severe consequences, potentially leading to complete compromise of the host system and the data it contains. Depending on the environment, this could affect a single server or spread to many hosts. The compromise of containerized environments can lead to data breaches, service disruption, and reputational damage. Given the sensitive nature of data often processed within containers, the impact can range from financial losses to regulatory penalties.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect potential container escapes.
*   Enable Elastic Defend integration to collect process data, and ensure Session View data is enabled to enhance visibility as mentioned in the setup guide.
*   Review and harden container configurations to minimize privileges granted to containerized processes, reducing the attack surface for escape attempts.
*   Implement network segmentation to limit the potential for lateral movement following a successful container escape.
*   Monitor process execution logs for unusual mount and chroot command sequences within container environments using Elastic Defend, SentinelOne, and Crowdstrike logs.
