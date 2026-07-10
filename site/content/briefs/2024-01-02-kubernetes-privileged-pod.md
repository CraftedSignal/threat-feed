---
title: Kubernetes Privileged Pod Creation or Update
slug: 2024-01-02-kubernetes-privileged-pod
description: Detection of Kubernetes privileged pods creation or update, which indicates an attempt to escalate privileges and gain full access to the host's namespace and devices, potentially leading to unauthorized access, data breaches, and service disruptions.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - kubernetes
  - privilege-escalation
  - cloud
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1204
    technique_name: User Execution
references:
  - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
rules:
  - title: Kubernetes Privileged Pod Creation
    description: Detects the creation of a privileged pod in Kubernetes by monitoring Kubernetes Audit logs for pod configurations that include root privileges.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1204
    data_sources:
      - webserver
      - linux
  - title: Kubernetes Privileged Pod Update
    description: Detects the update of a pod to a privileged state in Kubernetes by monitoring Kubernetes Audit logs for pod configurations that include root privileges.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1204
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This detection focuses on identifying the creation or updating of privileged pods within a Kubernetes environment. Privileged pods are containers configured to run with elevated privileges, effectively bypassing many of the security restrictions imposed by the container runtime. This can be achieved by setting the `privileged` flag to `true` in the pod's security context. While sometimes necessary for specific workloads, the presence of privileged pods significantly increases the attack surface of a Kubernetes cluster. An attacker who gains control of a privileged pod can potentially escalate privileges to the host node, compromise other containers in the cluster, and even gain access to sensitive data or resources. This detection leverages Kubernetes audit logs to identify pod configurations that explicitly request privileged access.

## Attack Chain

1.  An attacker gains initial access to a Kubernetes cluster, potentially through compromised credentials or a vulnerable application running within the cluster.
2.  The attacker attempts to create or update a pod configuration to include the `privileged: true` setting within the security context of the container.
3.  The Kubernetes API server receives the request to create or update the pod.
4.  The Kubernetes audit logging system records the API request, including the pod configuration details.
5.  The detection rule identifies the `privileged: true` setting in the audit logs, triggering an alert.
6.  If successful, the privileged pod is deployed within the cluster.
7.  The attacker leverages the elevated privileges within the pod to perform malicious activities, such as accessing sensitive data, modifying system configurations, or deploying malware.
8.  The attacker could then move laterally within the cluster, targeting other pods or nodes.

## Impact

A successful attack involving privileged pods can have severe consequences. Attackers can use privileged pods to escalate privileges to the host node, gaining complete control over the underlying infrastructure. This can lead to data breaches, service disruptions, and the compromise of sensitive information. The impact is especially high in environments where Kubernetes is used to manage critical applications or store sensitive data. Organizations across all sectors are potentially vulnerable.

## Recommendation

*   Enable Kubernetes audit logging and configure the audit policy to capture pod creation and update events. See the documentation in the references section.
*   Deploy the Sigma rule `Kubernetes Privileged Pod Creation` to your SIEM and tune for your specific environment.
*   Review existing pod configurations to identify and remediate any unnecessary privileged pods.
*   Implement the principle of least privilege when configuring pod security contexts.
*   Monitor the Kubernetes Audit logs for the specific events related to pod creation or updates using `kube_audit` log source.
