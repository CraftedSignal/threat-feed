---
title: Kubelet Pod Discovery Detected via Defend for Containers
slug: 2026-07-kubelet-pod-discovery
description: This rule detects the use of common Linux utilities such as du, nice, find, locate, and ls to repeatedly enumerate the /var/lib/kubelet/pods directory on a Kubernetes cluster, indicating an attacker attempting to discover running pods, their IDs, volumes, and runtime artifacts from a compromised container or node.
date: "2026-07-29T12:42:32Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - container
  - kubernetes
  - linux
  - discovery
products:
  - Kubernetes
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This rule detects the use of built-in utilities to discover running pods on a Kubernetes cluster. The utilities used are du, nice, find, locate, and ls. The "/var/lib/kubelet/pods" directory is the default location for Kubelet pod information.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: This rule detects use of common Linux utilities (ls, find, du, locate, nice) repeatedly targeting the Kubelet pods directory, including direct access to `/var/lib/kubelet/pods/*`. This matters because enumerating that path reveals pod IDs, volumes, and runtime artifacts that can accelerate container and cluster discovery.
    confidence_band: high
references:
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#kubelet-api
  - https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster
  - https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/
iocs:
  - type: filepath
    value: /var/lib/kubelet/pods
ioc_counts:
  filepath: 1
rules:
  - title: Kubelet Pod Discovery via Built-in Utilities
    description: Detects the use of common Linux utilities (du, nice, find, locate, ls) to enumerate the /var/lib/kubelet/pods directory, indicating Kubernetes pod discovery.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1083
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This brief details detection of Kubelet pod discovery, typically performed by an attacker who has gained initial access to a Kubernetes container or node. The attack involves the repeated use of standard Linux utilities like `ls`, `find`, `du`, `locate`, and `nice` to query the `/var/lib/kubelet/pods` directory. This directory is the default location where Kubelet stores critical information about running pods, including their IDs, associated volumes, and other runtime artifacts. Attackers leverage this behavior to map the cluster's workload distribution, identify potential targets, and locate sensitive data such as mounted secrets, service account tokens, or `kubeconfig` files. This discovery phase is a crucial step in preparing for further compromise, such as credential harvesting, privilege escalation, or lateral movement within the Kubernetes environment or to the underlying host. The activity can originate from an interactive session via `kubectl exec`, SSH to the node, or a compromised container using container runtime attach.

## Attack Chain

1. An attacker gains initial access to a Kubernetes container or node, potentially through a compromised application, exposed service, or misconfigured access.
2. From the compromised environment, the attacker executes a built-in Linux utility such as `ls`, `find`, `du`, `locate`, or `nice`.
3. The chosen utility is directed to enumerate or inspect the `/var/lib/kubelet/pods` directory, which contains details about active pods.
4. The attacker may use recursive commands like `find /var/lib/kubelet/pods -maxdepth 2` to systematically explore pod subdirectories and their contents.
5. The attacker collects information on pod IDs, volume mounts, and other runtime artifacts to understand the cluster's architecture and running workloads.
6. Discovered information is correlated to identify sensitive areas, such as pods with privileged settings or specific application data.
7. The attacker searches for sensitive files like mounted secrets, service account tokens, or `kubeconfig` files within the enumerated pod directories.
8. This discovery phase prepares the attacker for subsequent actions, including credential harvesting, privilege escalation, or lateral movement within the Kubernetes cluster.

## Impact

Successful Kubelet pod discovery can provide attackers with a detailed map of the Kubernetes cluster's running workloads and their configurations. This information is invaluable for identifying targets for privilege escalation, locating sensitive data, and planning lateral movement. If attackers gain access to `/var/lib/kubelet` via hostPath or privileged containers, they can read mounted secrets, service account tokens, and `kubeconfig` files, leading to credential harvesting. This can result in further compromise of the cluster, unauthorized access to cloud resources, data exfiltration, or complete control over the Kubernetes environment, potentially impacting numerous applications and services hosted within the cluster.

## Recommendation

* Deploy the Sigma rule in this brief to your SIEM and tune for your environment, specifically for `process_creation` events involving the listed utilities and directory.
* Monitor `process_creation` and `file_event` logs for repeated access or execution attempts targeting the `/var/lib/kubelet/pods` directory, which is referenced in the detection rule.
* Restrict unnecessary hostPath mounts to `/var/lib/kubelet` and other critical node paths to prevent attackers from accessing sensitive host directories.
* Implement admission controls to block privileged or `hostPID` containers, and enforce non-root and read-only root filesystems for containers.
* Validate the actor's permissions and activity by correlating with Kubernetes API audit logs, particularly for users or service accounts involved in activity against `/var/lib/kubelet/pods`.
