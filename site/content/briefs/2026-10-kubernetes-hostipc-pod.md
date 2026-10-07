---
title: Kubernetes Pod Creation with HostIPC Namespace
slug: 2026-10-kubernetes-hostipc-pod
description: Adversaries can exploit the hostIPC namespace in Kubernetes pods to access host-level shared memory and IPC mechanisms, enabling container escape and privilege escalation.
date: "2026-10-07T16:36:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container-security
  - kubernetes
  - privilege-escalation
vendors:
  - Kubernetes
products:
  - Kubernetes
references:
  - https://research.nccgroup.com/2021/11/10/detection-engineering-for-kubernetes-clusters/#part3-kubernetes-detections
  - https://kubernetes.io/docs/concepts/security/pod-security-admission/
  - https://bishopfox.com/blog/kubernetes-pod-privilege-escalation
rules:
  - title: Detect Kubernetes Pod Created With HostIPC
    description: Detects the creation or modification of a Kubernetes pod where hostIPC is enabled, which may indicate an attempt to perform container escape or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - privilege-escalation
    techniques:
      - T1610
      - T1611
    data_sources:
      - webserver
rules_count: 1
---

This threat involves the unauthorized creation or modification of Kubernetes pods with the 'hostIPC' namespace enabled. By setting hostIPC to true, a pod gains the ability to share the host's Inter-Process Communication (IPC) namespace. This configuration allows the pod to access shared memory, semaphore arrays, and message queues used by other processes running on the same host node. 

Defenders must recognize that while this setting is occasionally used for legitimate debugging or monitoring agents, it represents a significant security risk. An attacker who successfully deploys a malicious container with this configuration can perform reconnaissance by inspecting IPC facilities or perform privilege escalation by intercepting or manipulating data within shared memory segments. Defenders should monitor Kubernetes audit logs for pod creation, update, or patch operations where the 'hostIPC' property is set to true and reconcile these against a baseline of approved infrastructure images.

## Attack Chain

1. Attacker gains access to the Kubernetes API server via compromised credentials or an exploited service account.
2. Attacker prepares a malicious pod specification file with 'hostIPC: true' defined in the pod template.
3. Attacker uses 'kubectl' or direct API calls to submit the malicious pod configuration (create, update, or patch operation).
4. Kubernetes controller validates the request and schedules the pod on a worker node with the host IPC namespace mounted.
5. Attacker executes shell commands within the running pod to access /dev/shm or use the 'ipcs' utility to enumerate host-level IPC facilities.
6. Attacker interacts with identified shared memory, semaphores, or message queues to extract sensitive data or inject malicious payloads.
7. Attacker achieves container escape or privilege escalation by manipulating host processes via the shared IPC mechanisms.

## Impact

Successful exploitation allows attackers to bypass container isolation boundaries, leading to unauthorized access to data processed by host-level services, potential container escape, and escalation of privileges from the container context to the host node. This significantly compromises the integrity and confidentiality of the entire node.

## Recommendation

1. Deploy the provided Sigma rule to monitor Kubernetes audit logs for suspicious pod specifications.
2. Maintain a strict allowlist of container images authorized to utilize the hostIPC namespace, such as monitoring or logging agents, and exclude them from detection logic.
3. Implement Kubernetes Pod Security Admissions to restrict the usage of privileged namespaces like hostIPC in production namespaces.
4. Conduct regular audits of active pods and configurations to identify and remediate instances where hostIPC is enabled without valid justification.
5. Isolate affected pods immediately if unauthorized access to host IPC mechanisms is detected.
