---
title: Suspicious Container Runtime CLI Execution
slug: 2024-01-container-runtime-cli-abuse
description: The rule detects execution of container runtime CLI tools (ctr, crictl, nerdctl) with arguments indicating container creation, command execution inside existing containers, image manipulation, or host filesystem mounting, potentially leading to container escape and privilege escalation.
date: "2024-01-03T18:51:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - execution
  - privilege_escalation
  - linux
vendors:
  - Elastic
products:
  - Elastic Defend for Containers
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
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/execution_container_runtime_cli_suspicious_args.toml
rules:
  - title: Suspicious Container Runtime CLI Execution - Privileged Container
    description: Detects execution of container runtime CLIs (ctr, crictl, nerdctl) with arguments indicative of creating privileged containers.
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
  - title: Suspicious Container Runtime CLI Execution - Exec into Container
    description: Detects execution of container runtime CLIs (ctr, crictl, nerdctl) to execute commands inside an existing container.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1609
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Containerd Socket Access from Temp Directory
    description: Detects processes running from /tmp or /dev/shm accessing containerd socket
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1609
      - T1611
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This detection identifies suspicious use of container runtime CLI tools (ctr, crictl, nerdctl) on Linux hosts. These tools, when used with specific arguments, can bypass Kubernetes API server controls, RBAC authorization, admission webhooks, pod security standards, and Kubernetes audit logging. Attackers with host-level access can leverage these CLIs to create privileged containers, execute commands within other pods, manipulate container images, and mount host filesystems, thereby gaining unauthorized access and potentially escalating privileges within the cluster. The Elastic Defend for Containers integration introduced in version 9.3.0 provides the necessary data source for detecting such activity.

## Attack Chain

1. An attacker gains host-level access to a Kubernetes node, possibly through exploiting a vulnerability or gaining unauthorized credentials.
2. The attacker uses a container runtime CLI tool (ctr, crictl, or nerdctl) to interact directly with the container runtime socket.
3. The attacker executes commands like `ctr tasks exec` to run commands inside an existing container, potentially targeting a pod with sensitive information.
4. Alternatively, the attacker may use commands like `ctr run --privileged` to create a new, privileged "ghost container" with elevated privileges on the host.
5. The attacker leverages the privileged container or compromised pod to steal service account tokens and secrets.
6. The attacker can also use image manipulation commands to pull attacker-controlled images from external registries into the cluster.
7. The attacker mounts the host filesystem into a container using `ctr run --mount` to gain direct access to sensitive host files.
8. The attacker uses the gained privileges and access to move laterally within the Kubernetes cluster or exfiltrate sensitive data.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, privilege escalation within the Kubernetes cluster, and potential compromise of the entire cluster. Attackers can steal service account tokens and secrets, gain control over containers, and potentially escape to the host system. The lack of Kubernetes-level monitoring makes these actions difficult to detect using standard Kubernetes auditing tools.

## Recommendation

*   Deploy the "Suspicious Container Runtime CLI Execution" Sigma rule to your SIEM to detect malicious usage of container runtime CLIs.
*   Tune the Sigma rule by filtering legitimate parent processes, users, or host roles that may use these CLIs (e.g., platform automation, node bootstrap).
*   Investigate any alerts generated by the Sigma rule by reviewing the full argv list, working directory, and referenced images or bundles to determine if the activity is authorized.
*   Monitor file, network, and Kubernetes audit activity for pulls from unusual registries or subsequent pod changes that may be related to suspicious CLI executions.
