---
title: Potential Direct Kubelet API Access via Process Arguments
slug: 2024-01-09-kubelet-access
description: This rule detects potential direct Kubelet API access attempts on Linux by identifying process executions whose arguments contain URLs targeting Kubelet ports (10250/10255) enabling discovery and lateral movement in Kubernetes environments.
date: "2026-05-04T21:18:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - kubelet
  - lateral-movement
  - discovery
  - execution
  - linux
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#kubelet-api
  - https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster
  - https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/
rules:
  - title: Kubelet API Access via Process Arguments
    description: Detects potential direct Kubelet API access attempts by identifying process executions with arguments containing URLs targeting Kubelet ports.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - lateral_movement
    techniques:
      - T1021
      - T1613
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Kubelet Access via Scripting Interpreter
    description: Detects potential direct Kubelet API access attempts via scripting interpreters using process arguments with URLs targeting Kubelet ports.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
      - lateral_movement
    techniques:
      - T1021
      - T1059.004
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This detection identifies potential direct Kubelet API access attempts on Linux systems. The Kubelet, acting as the primary node agent, exposes an API accessible via ports 10250 and 10255. Attackers may exploit this API to enumerate pods, fetch logs, or even attempt remote execution. This access can lead to significant breaches in Kubernetes environments, facilitating discovery, lateral movement, and ultimately, compromise of sensitive data or control over cluster resources. The detection focuses on identifying process executions where the command-line arguments contain URLs targeting these Kubelet ports, indicating a potential attempt to interact with the Kubelet API directly.

## Attack Chain

1.  An attacker gains initial access to a compromised host within the Kubernetes cluster or a host with network access to the Kubelet ports.
2.  The attacker uses a utility like `curl`, `wget`, `python`, or similar tools to craft an HTTP request targeting the Kubelet API on ports 10250 or 10255.
3.  The request includes a path like `/pods`, `/runningpods`, `/metrics`, `/exec`, or `/containerLogs` to gather information about the cluster's state and configuration.
4.  The attacker examines the response to identify potential targets for lateral movement, such as specific pods or containers of interest.
5.  The attacker attempts to execute commands within a container using the `/exec` endpoint, potentially leveraging exposed service account tokens or other credentials.
6.  The attacker uses gathered information to move laterally to other pods or nodes within the cluster, escalating privileges as they go.
7.  The attacker compromises sensitive data or critical applications running within the Kubernetes cluster.

## Impact

Successful exploitation can lead to full cluster compromise. Attackers can gain unauthorized access to sensitive data, disrupt critical applications, and move laterally to other resources within the Kubernetes environment. This could lead to significant financial losses, reputational damage, and legal liabilities. The potential impact includes data breaches, denial of service, and complete control over the Kubernetes infrastructure.

## Recommendation

*   Deploy the Sigma rule `Kubelet API Access via Process Arguments` to your SIEM to detect suspicious process executions.
*   Restrict access to Kubelet ports 10250/10255 at the network layer to limit pod-to-node or host-to-node traffic as recommended in the overview section.
*   Harden Kubelet configuration by disabling anonymous authentication and enforcing webhook authentication/authorization as described in the overview section.
