---
title: Nsenter to PID Namespace via Auditd
slug: 2024-01-03-nsenter-pid-namespace
description: This rule detects nsenter executions that target a PID with a namespace target flag, a common pattern used to attach to the host init namespace from a container or session and run with host context, potentially escalating privileges.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - linux
  - container
vendors:
  - Elastic
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://attack.mitre.org/techniques/T1611/
  - https://man7.org/linux/man-pages/man1/nsenter.1.html
  - https://docs.elastic.co/integrations/auditd_manager
rules:
  - title: Nsenter to PID Namespace via Auditd
    description: Detects nsenter executions that target PID with a namespace target flag, a pattern commonly used to attach to the host init namespace from a container or session and run with host context.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: Nsenter with Target and Namespace Flags
    description: Detects nsenter executions that include both a target PID and namespace flags.
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

This detection identifies instances where the `nsenter` command is used to enter a process namespace, specifically targeting a PID. This technique is often employed to attach to the host's init namespace from a container or session, effectively allowing the attacker to execute commands within the host's context. This behavior is concerning because it can be used to escalate privileges and gain unauthorized access to the underlying system. This is especially relevant in containerized environments where attackers may attempt to escape the container and access the host system. The rule leverages Auditd logs to identify these `nsenter` executions, focusing on those that include the `--target` or `-t` flags, which specify the target PID for namespace entry.

## Attack Chain

1. An attacker gains initial access to a container or a restricted session on a Linux host.
2. The attacker identifies a target PID, often the init process (PID 1), to enter its namespace.
3. The attacker executes the `nsenter` command with the `--target` or `-t` flag, specifying the target PID. Additional namespace flags like `--mount`, `--uts`, `--ipc`, `--net`, and `--user` may also be used.
4. Auditd logs the `nsenter` execution, capturing the process name, arguments, and other relevant metadata.
5. The detection rule identifies the `nsenter` execution based on the command name and the presence of the `--target` or `-t` flag.
6. The attacker, now within the target PID's namespace, executes commands with the privileges of that process. This may include reading sensitive files, modifying system configurations, or executing malicious code.
7. The attacker leverages the escalated privileges to further compromise the host system, potentially gaining root access or deploying malware.
8. The attacker establishes persistence mechanisms to maintain access to the compromised host, such as creating new systemd units or modifying existing ones.

## Impact

Successful exploitation can lead to complete compromise of the host system. Attackers can gain root privileges, access sensitive data, and deploy malware. In containerized environments, this can allow attackers to escape the container and access the underlying host, potentially affecting other containers running on the same host. The impact is especially significant in production environments where compromised hosts can disrupt critical services and expose sensitive data.

## Recommendation

*   Deploy the Auditd Manager integration on Linux hosts to collect process execution telemetry, as specified in the [setup instructions](#setup).
*   Implement the Sigma rule "Nsenter to PID Namespace via Auditd" to detect suspicious `nsenter` executions.
*   Tune the Sigma rule by excluding known false positives, such as legitimate `nsenter` executions by platform engineers or CNI/snap workflows, as mentioned in the [false positives section](#false-positive-analysis).
*   Investigate any detected `nsenter` executions by reviewing process arguments, parent processes, user identities, and host information, as outlined in the [triage and analysis section](#triage-and-analysis).
*   Isolate any compromised hosts, revoke credentials, inspect for persistence, and re-image if integrity cannot be proven, as recommended in the [response and remediation section](#response-and-remediation).
