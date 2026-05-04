---
title: Kubeletctl Execution Inside Container Detected
slug: 2024-01-kubeletctl-container-execution
description: This rule detects the execution of kubeletctl inside a container, which can be used to enumerate the Kubelet API or other resources inside the container, potentially indicating lateral movement attempts within the pod.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container
  - kubeletctl
  - lateral-movement
  - execution
vendors:
  - Elastic
products:
  - Defend for Containers
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
references:
  - https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster
  - https://github.com/cyberark/kubeletctl
rules:
  - title: Detect Kubeletctl Execution in Container
    description: Detects the execution of kubeletctl inside a container, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1609
    data_sources:
      - process_creation
      - linux
  - title: Detect Kubeletctl Execution with Specific Arguments
    description: Detects kubeletctl execution with arguments associated with container enumeration and exploitation.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.004
      - T1609
      - T1613
    data_sources:
      - process_creation
      - linux
  - title: Detect interactive container execution
    description: Detects interactive execution inside a container
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This rule detects the execution of `kubeletctl` inside a container. Kubeletctl is a command-line tool that interacts with the Kubelet API directly, making the often undocumented API more accessible. Attackers may use it to enumerate the Kubelet API or other resources within the container, potentially indicating lateral movement within the pod. The detection is based on the "Defend for Containers" integration (version 9.3.0 and later) within the Elastic stack. This activity is significant because `kubeletctl` can expose pod and node details, enabling actions that facilitate discovery and lateral movement from a compromised container.

## Attack Chain

1. An attacker gains initial access to a container, possibly through a vulnerability in the containerized application or a misconfigured Kubernetes environment.
2. The attacker executes `kubeletctl` inside the compromised container. This could be facilitated by the tool being present in the container image or downloaded post-compromise.
3. The attacker uses `kubeletctl scan` to discover Kubelet endpoints within the Kubernetes cluster.
4. The attacker leverages `kubeletctl pods` or `kubeletctl runningpods` to enumerate running pods and their details.
5. The attacker uses the discovered pod information to identify potential targets for lateral movement.
6. The attacker attempts to use `kubeletctl exec` or `kubeletctl attach` to gain access to other pods within the cluster.
7. The attacker attempts to port forward using `kubeletctl portForward` to establish connections to services running in other pods.
8. Upon successful lateral movement, the attacker performs further reconnaissance or deploys malicious payloads to achieve their objectives, such as data exfiltration or denial-of-service.

## Impact

Successful execution of `kubeletctl` within a container can lead to the exposure of sensitive information about the Kubernetes cluster, including pod details and internal network configurations. This can enable attackers to move laterally within the cluster, potentially compromising other applications and data. The impact could range from data breaches and service disruptions to full cluster compromise depending on the attacker's objectives and the scope of the compromised container's access.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect the execution of `kubeletctl` within containers based on process name and arguments.
*   Monitor container network activity for connections to node addresses on Kubelet ports (commonly 10250/10255) and investigate any suspicious patterns.
*   Implement network policies to restrict pod-to-node access to the Kubelet API.
*   Harden container images by removing unnecessary tools like `kubeletctl` and enforce least privilege principles.
*   Enable and review Kubernetes audit logs to identify the source of interactive sessions into containers, correlating with timestamps of `kubeletctl` execution.
*   Enforce Pod Security Standards to restrict privileged pods and limit node API exposure.
