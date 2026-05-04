---
title: Kubelet API Connection Attempt to Internal IP
slug: 2024-01-kubelet-api-connection
description: The rule detects network connection attempts to the Kubernetes Kubelet API ports 10250 and 10255 on internal IP ranges from Linux hosts, indicating potential lateral movement within container and cluster environments.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - lateral-movement
  - kubelet
  - linux
  - container
vendors:
  - Elastic
  - Kubernetes
products:
  - kubelet
  - Elastic Defend
  - auditd_manager
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
references:
  - https://attack.mitre.org/techniques/T1021/
  - https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/
  - https://attack.mitre.org/techniques/T1613/
rules:
  - title: Kubelet API Connection Attempt from Suspicious Process
    description: Detects network connections to Kubelet API port 10250 or 10255 from processes running in temporary directories.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021
    data_sources:
      - network_connection
      - linux
  - title: Kubelet API Connection with Common Utilities
    description: Detects network connections to Kubelet API from common utilities like curl, wget, nc, etc.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

This detection rule identifies suspicious network connections to the Kubernetes Kubelet API, specifically targeting ports 10250 and 10255, from Linux hosts within internal network ranges. Attackers frequently exploit weak authentication or network controls to access the Kubelet API, potentially enabling them to enumerate pods, retrieve logs, and execute commands on nodes. This activity often originates from common scripting utilities like `curl`, `wget`, or interpreters like `python` and `node`, particularly when executed from world-writable directories such as `/tmp`, `/var/tmp`, or `/dev/shm`. This technique is often a component of container and cluster lateral movement, where the attacker seeks to expand their access within the Kubernetes environment. The rule is designed to detect these unauthorized attempts and alert security teams to investigate potential breaches.

## Attack Chain

1.  An attacker gains initial access to a compromised container or host within the Kubernetes cluster, potentially through exploiting a vulnerability in a running application.
2.  The attacker executes a reconnaissance command, such as `curl` or `wget`, from within the compromised container, targeting the Kubelet API on port 10250 or 10255.
3.  The `curl` or `wget` command is executed from a temporary directory like `/tmp` or `/dev/shm` to avoid detection.
4.  The attacker attempts to enumerate running pods and services by querying the `/pods` or `/runningpods` endpoints of the Kubelet API.
5.  If successful, the attacker identifies a target pod within the cluster based on the enumerated information.
6.  The attacker leverages the Kubelet API to execute commands within the target pod, potentially escalating privileges or accessing sensitive data.
7.  The attacker attempts to move laterally to other nodes or containers within the Kubernetes cluster, repeating the reconnaissance and exploitation steps.
8.  The ultimate goal is to gain control over the entire Kubernetes cluster, enabling data exfiltration, resource hijacking, or disruption of services.

## Impact

Successful exploitation of the Kubelet API can lead to a complete compromise of the Kubernetes cluster. Attackers can gain unauthorized access to sensitive data, escalate privileges, and disrupt critical services. While the number of victims may vary depending on the organization's security posture, a successful attack could impact all applications and data managed by the cluster. Organizations in any sector utilizing Kubernetes are potentially at risk.

## Recommendation

*   Enable syscall auditing and ensure that `event.category:network` events are generated for network connections, as outlined in the rule's setup guide.
*   Deploy the provided Sigma rule to your SIEM and tune it based on your environment to reduce false positives.
*   Restrict pod-to-node access to port 10250 using network policies or security groups to limit the attack surface, as noted in the rule's documentation.
*   Implement Kubernetes API audit logging to detect unauthorized access attempts and credential access, correlating with process argument telemetry as mentioned in the triage steps.
