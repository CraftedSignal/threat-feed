---
title: Container Runtime CLI Execution with Suspicious Arguments
slug: 2024-01-03-container-runtime-cli-suspicious-arguments
description: Detects execution of container runtime CLI tools (ctr, crictl, nerdctl) with arguments indicating container creation, command execution inside existing containers, image manipulation, or host filesystem mounting, potentially leading to privileged container creation and unauthorized access to sensitive data.
date: "2024-01-03T14:27:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - execution
  - privilege-escalation
  - linux
vendors:
  - Elastic
products:
  - Elastic Defend
  - Auditbeat
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
references:
  - https://attack.mitre.org/techniques/T1609/
  - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation
rules:
  - title: Container Runtime CLI Execution with Suspicious Arguments
    description: Detects execution of container runtime CLI tools (ctr, crictl, nerdctl) with arguments indicating container creation, command execution inside existing containers, image manipulation, or host filesystem mounting.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1609
      - T1611
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Container Runtime Socket Access from Temporary Locations
    description: Detects processes running from /tmp, /dev/shm or /var/tmp accessing container runtime sockets, indicating potential container escape attempts.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection rule identifies the execution of container runtime CLI tools (ctr, crictl, nerdctl) with suspicious arguments, indicating malicious activity within a containerized environment. Attackers leveraging host-level access can exploit these tools to bypass Kubernetes API server, RBAC authorization, admission webhooks, pod security standards, and Kubernetes audit logging. This allows attackers to create privileged "ghost" containers, execute commands within other pods to steal service account tokens and secrets, pull attacker-controlled images, and destroy evidence, all while remaining undetected by traditional Kubernetes-level monitoring. The rule specifically focuses on the use of `ctr`, `crictl`, and `nerdctl` with arguments related to task execution, privileged container creation, and snapshot mounting.

## Attack Chain

1.  Attacker gains initial host-level access through a compromised node or other vulnerability.
2.  Attacker utilizes a container runtime CLI tool (`ctr`, `crictl`, or `nerdctl`) to interact directly with the container runtime socket.
3.  The attacker executes `ctr tasks exec` with a specified container ID to gain shell access within the targeted container.
4.  Alternatively, the attacker uses `ctr run --privileged` to create a new, highly privileged container, effectively bypassing security policies.
5.  The attacker mounts host filesystems into the container using `ctr run --mount`, granting them access to sensitive host data.
6.  Attacker pulls malicious images from untrusted registries using `ctr pull <malicious_image>`, introducing potentially compromised software into the environment.
7.  The attacker leverages access to steal service account tokens and other secrets from targeted pods.
8.  The attacker uses the compromised environment to move laterally within the cluster, escalate privileges, and exfiltrate sensitive data.

## Impact

Successful exploitation can lead to a complete compromise of the Kubernetes cluster. Attackers can gain unauthorized access to sensitive data, escalate privileges, and move laterally within the environment. The bypass of standard Kubernetes security controls makes detection difficult, allowing attackers to operate undetected for extended periods.

## Recommendation

*   Deploy the Sigma rule "Container Runtime CLI Execution with Suspicious Arguments" to your SIEM to detect suspicious container runtime CLI executions (rule: Container Runtime CLI Execution with Suspicious Arguments).
*   Enable process execution telemetry with arguments from Elastic Defend and/or Auditd Manager to provide the necessary data for detection (setup instructions in the rule description).
*   Tune the Sigma rule by filtering out legitimate parent processes, users, or host roles known to use these CLIs, to reduce false positives (false_positives in the rule description).
*   Review and restrict host-level access to nodes to minimize the attack surface for this type of exploit (overview).
*   Implement strict image scanning and registry controls to prevent the introduction of malicious images into the environment (attack chain step 6).
*   Monitor file, network, and Kubernetes audit activity for pulls from unusual registries or subsequent pod changes to identify suspicious container activity (note).
