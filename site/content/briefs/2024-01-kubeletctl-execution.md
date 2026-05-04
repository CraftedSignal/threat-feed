---
title: Potential Kubeletctl Execution on Linux Hosts
slug: 2024-01-kubeletctl-execution
description: This rule detects the execution of kubeletctl, a command-line tool used to interact with the Kubelet API, on Linux hosts, potentially leading to discovery and lateral movement within Kubernetes environments.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - kubeletctl
  - container
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
references:
  - https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster
  - https://github.com/cyberark/kubeletctl
rules:
  - title: Potential Kubeletctl Execution
    description: Detects the execution of kubeletctl, a command-line tool for interacting with the Kubelet API.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1609
      - T1613
    data_sources:
      - process_creation
      - linux
  - title: Kubeletctl Execution with Sensitive Arguments
    description: Detects the execution of kubeletctl with arguments that could be used for discovery or execution.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
    techniques:
      - T1609
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The kubeletctl tool simplifies access to Kubelet endpoints, potentially allowing attackers to perform discovery and lateral movement within Kubernetes environments. The tool can be used to enumerate pods and nodes, and attempt actions such as exec/attach/portForward. Attackers may run `kubeletctl scan` to find reachable Kubelet endpoints, then use `pods` or `exec/attach` for follow-on access. This activity is typically observed on Linux hosts within containerized environments. Defenders should monitor for the execution of kubeletctl with suspicious arguments or connections to Kubelet ports (commonly 10250/10255).

## Attack Chain

1.  Attacker gains initial access to a compromised host within the Kubernetes environment.
2.  Attacker downloads or transfers the `kubeletctl` binary to the compromised host.
3.  Attacker executes `kubeletctl scan` to identify accessible Kubelet API endpoints by scanning for open ports 10250 and 10255.
4.  Attacker uses `kubeletctl pods` to enumerate running pods on a targeted node based on the scan results.
5.  Attacker leverages `kubeletctl exec` or `kubeletctl attach` to gain shell access to a pod.
6.  Attacker uses the compromised pod to move laterally within the Kubernetes cluster, potentially accessing sensitive data or resources.
7.  Attacker may attempt to access Kubernetes credentials, such as service account tokens or kubeconfigs, for further privilege escalation.

## Impact

Successful exploitation can allow attackers to enumerate pods and nodes, execute commands within containers, and potentially move laterally within the Kubernetes cluster. This could lead to unauthorized access to sensitive data, resource hijacking, or complete compromise of the Kubernetes environment. The CyberArk research cited in the references describes how kubeletctl can be leveraged to attack Kubernetes clusters.

## Recommendation

*   Deploy the Sigma rule `Potential Kubeletctl Execution` to detect suspicious execution of the `kubeletctl` binary on Linux hosts, focusing on command-line arguments such as `scan`, `pods`, `exec`, and `attach`.
*   Monitor host and container telemetry for connections to Kubelet ports (10250/10255) using a network connection rule and look for scanning patterns across multiple nodes.
*   Restrict access to Kubelet ports at the network layer and harden Kubelet authentication/authorization based on the recommendations in the provided references.
*   Rotate/revoke any exposed Kubernetes credentials (service account tokens, kubeconfigs, client certs) and investigate for follow-on discovery or execution attempts.
