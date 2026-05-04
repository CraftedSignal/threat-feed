---
title: Potential Direct Kubelet Access via Process Arguments
slug: 2024-01-kubelet-access
description: Detection of potential direct Kubelet access via process arguments in Linux containers, which could lead to enumeration, execution, or lateral movement within the Kubernetes cluster.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container
  - kubelet
  - kubernetes
  - lateral-movement
  - execution
vendors:
  - Elastic
products:
  - Defend for Containers
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#kubelet-api
  - https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster
  - https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/
rules:
  - title: Potential Direct Kubelet Access via Process Arguments
    description: Detects potential direct Kubelet access via process arguments by monitoring process creations for HTTP requests targeting Kubelet API ports.
    platform: sigma
    severity: high
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1021
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Potential Direct Kubelet Access via Wget
    description: Detects potential direct Kubelet access via process arguments using wget to target Kubelet API ports.
    platform: sigma
    severity: high
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1021
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This rule detects potential direct Kubelet access via process arguments within Linux containers. Attackers may target the Kubelet API to gain unauthorized access to the Kubernetes API server or other sensitive resources within the cluster. Observed requests are often used for reconnaissance, such as enumerating pods and cluster resources, or for executing commands directly on the API server. This activity indicates a potential attempt to move laterally within the Kubernetes environment. The activity is detected by monitoring process arguments for HTTP requests directed at the Kubelet API on ports 10250 or 10255. The detection leverages Elastic Defend for Containers, introduced in version 9.3.0.

## Attack Chain

1. An attacker gains initial access to a container within the Kubernetes cluster, potentially through exploiting a vulnerable application.
2. The attacker opens an interactive shell within the compromised container.
3. Using command-line tools such as `curl` or `wget`, the attacker crafts an HTTP request targeting the Kubelet API, typically on port 10250 or 10255.
4. The HTTP request is embedded within the process arguments, including specific Kubelet endpoints such as `/pods`, `/exec`, `/run`, or `/logs`.
5. The attacker attempts to enumerate pods and other cluster resources by querying the `/pods` endpoint.
6. The attacker attempts to execute commands within containers by leveraging the `/exec` or `/run` endpoints.
7. The attacker attempts to retrieve container logs using the `/logs` endpoint.
8. Successful exploitation allows the attacker to move laterally within the Kubernetes cluster, potentially gaining access to sensitive data or control over other resources.

## Impact

Successful exploitation of direct Kubelet access can lead to significant compromise within a Kubernetes cluster. Attackers can enumerate sensitive information, execute arbitrary commands within containers, and move laterally to other parts of the cluster. This can result in data exfiltration, denial of service, or complete cluster takeover. Due to the high level of access granted by Kubelet, a successful attack allows the attacker to take complete control over the target node.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM and tune them for your environment. Enable Elastic Defend for Containers with a minimum version of 9.3.0 to generate the necessary logs for these detections.
*   Review network policies to restrict pod access to Kubelet ports (10250, 10255) except from approved node-local agents (references: https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster).
*   Harden Kubelet authentication and authorization by disabling anonymous access and requiring webhook authorization (references: https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/).
*   Enforce pod security policies to restrict privileged pods and host networking, reducing the attack surface for node API access.
