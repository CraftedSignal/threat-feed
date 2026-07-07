---
title: GKE Pod Created With HostIPC Sharing
slug: 2026-07-gcp-gke-host-ipc-escalation
description: A privilege escalation threat in Google Kubernetes Engine (GKE) involves an attacker creating or modifying a pod to enable host Inter-Process Communication (IPC) namespace sharing, which exposes host IPC mechanisms and can lead to privilege escalation within the cluster by allowing the pod to interact directly with the underlying host's processes.
date: "2026-07-06T16:54:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - gcp
  - kubernetes
  - privilege-escalation
  - container-security
  - cloud-security
  - host-ipc
vendors:
  - Google
products:
  - Google Kubernetes Engine (GKE)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: Detects GKE pod create, update, or patch events that enable host IPC namespace sharing. This exposes host inter-process communication mechanisms and can support privilege escalation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1610
    technique_name: Deploy Container
    evidence: Detects GKE pod create, update, or patch events that enable host IPC namespace sharing.
    confidence_band: high
references:
  - https://kubernetes.io/docs/concepts/security/pod-security-standards/
  - https://bishopfox.com/blog/kubernetes-pod-privilege-escalation
rules:
  - title: GKE Pod Created With HostIPC
    description: Detects GKE pod create, update, or patch events that enable host IPC namespace sharing, which can support privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1610
      - T1611
    data_sources:
      - cloud
      - gcp
rules_count: 1
---

This threat brief describes a privilege escalation vector in Google Kubernetes Engine (GKE) where an attacker with appropriate permissions creates or modifies a Kubernetes pod to enable `hostIPC` namespace sharing. This configuration allows the pod to access and manipulate Inter-Process Communication (IPC) mechanisms on the underlying host node, potentially leading to unauthorized access and control over the host operating system. This technique is a well-known method for container escape and privilege escalation in Kubernetes environments, enabling a compromised pod to break out of its isolation and affect other workloads or the cluster infrastructure. Defenders should focus on detecting this specific pod configuration to prevent adversaries from elevating their privileges within GKE clusters.

## Attack Chain

1.  **Initial Access**: An attacker gains initial access to the GKE cluster, potentially through compromised credentials, exploitation of a vulnerable application running within a pod, or misconfigured access controls.
2.  **Privilege Discovery**: The attacker assesses their current permissions within the cluster, identifying roles or service accounts that allow for pod creation, update, or patching.
3.  **Malicious Pod Specification**: The attacker crafts a Kubernetes pod specification that includes `hostIPC: true` in its configuration.
4.  **Pod Creation/Modification**: The attacker either creates a new pod with the malicious specification or patches an existing pod to enable `hostIPC` sharing. This action requires specific API permissions within the GKE cluster.
5.  **Host IPC Access**: The newly created or modified pod is now able to interact with the host system's IPC facilities, such as System V IPC or POSIX message queues.
6.  **Privilege Escalation**: The attacker leverages the host IPC access to exploit vulnerabilities or misconfigurations on the host node, allowing them to gain elevated privileges or achieve a container escape.
7.  **Impact**: With host-level privileges, the attacker can then perform further actions, including lateral movement to other nodes, data exfiltration from the host, or disruption of critical cluster services.

## Impact

Successful exploitation of this privilege escalation technique allows an attacker to break out of the container's isolation and gain elevated privileges on the underlying GKE host node. This can lead to a complete compromise of the node, enabling the adversary to access sensitive data, install malicious software, disrupt services running on the node, or potentially move laterally to other nodes or even the entire Kubernetes cluster control plane. While no specific victim count is provided, any organization utilizing GKE clusters is susceptible if proper security controls are not in place to prevent or detect such configurations.

## Recommendation

*   Deploy the Sigma rule "GKE Pod Created With HostIPC" to your SIEM to detect attempts to create or modify pods with host IPC enabled.
*   Ensure GKE audit logging is enabled and configured to capture `io.k8s.core.v1.pods.create`, `io.k8s.core.v1.pods.update`, and `io.k8s.core.v1.pods.patch` events for the `gcp.audit` log source.
*   Implement and enforce Pod Security Standards (PSS) or Pod Security Policies (PSP, deprecated) in your GKE clusters to prevent the deployment of pods with `hostIPC: true` in untrusted namespaces.
*   Baseline legitimate usage of `hostIPC` in your environment and configure exclusions in the "GKE Pod Created With HostIPC" rule for trusted users or namespaces if necessary, after thorough review.
