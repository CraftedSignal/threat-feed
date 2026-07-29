---
title: Kubernetes Service Account Namespace File Read for Discovery
slug: 2026-07-kubernetes-service-account-namespace-read
description: Adversaries gaining initial access to a Kubernetes pod often read the service account namespace file, located at `/var/run/secrets/kubernetes.io/serviceaccount/namespace` or `/run/secrets/kubernetes.io/serviceaccount/namespace`, to identify the container's namespace and understand its context, enabling further discovery and lateral movement within the Kubernetes environment.
date: "2026-07-29T12:45:58Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - container
  - discovery
  - kubernetes
  - linux
  - elastic-defend
products:
  - Kubernetes
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: The service account namespace file is used to identify the namespace of the container in which it is running, and may be used by an adversary to get a better understanding of the container and the services running inside it.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: after landing a shell in a pod, the attacker reads the namespace file, then issues namespace-scoped kubectl or direct API calls to list Deployments, Secrets, and ServiceAccounts, map privileges and service endpoints, and plan targeted lateral movement within that namespace.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This rule flags a process inside a container opening /var/run/secrets/kubernetes.io/serviceaccount/namespace, which reveals the pod’s Kubernetes namespace.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/discovery_service_account_namespace_read.toml
rules:
  - title: Kubernetes Service Account Namespace File Read - File Event
    description: Detects suspicious file open events on the Kubernetes service account namespace file, indicative of an adversary performing discovery within a compromised container.
    platform: sigma
    severity: low
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1082
      - T1613
    data_sources:
      - file_event
      - linux
  - title: Kubernetes Service Account Namespace File Read - Process Execution
    description: Detects execution of common utilities used to read the Kubernetes service account namespace file, indicating adversary discovery within a compromised container.
    platform: sigma
    severity: low
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1082
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This brief details a common post-compromise activity observed in Kubernetes environments where an adversary reads the service account namespace file to gain situational awareness. After successfully compromising a container and obtaining a shell, attackers often seek to understand their current environment. Reading the service account namespace file, typically found at `/var/run/secrets/kubernetes.io/serviceaccount/namespace` or `/run/secrets/kubernetes.io/serviceaccount/namespace`, provides immediate insight into the Kubernetes namespace the container belongs to. This seemingly benign action is a crucial first step for adversaries to orient themselves, map privileges, identify service endpoints, and plan subsequent discovery activities. The detection targets file open events on these specific paths and the execution of common command-line utilities (like `cat`, `head`, `tail`, `more`, `less`, `sed`, `awk`) used to read the file's contents, providing defenders with an early indicator of adversary discovery efforts within a compromised pod.

## Attack Chain

1. An adversary gains initial access to a Kubernetes pod, typically by exploiting a vulnerable application or misconfiguration, obtaining a shell inside the container.
2. The adversary executes commands such as `cat`, `head`, or `less` to read the content of `/var/run/secrets/kubernetes.io/serviceaccount/namespace` or `/run/secrets/kubernetes.io/serviceaccount/namespace`.
3. The attacker uses the extracted namespace information to establish their current context and identify the specific Kubernetes namespace they are operating within.
4. Leveraging this information, the adversary performs further discovery within the identified namespace using `kubectl` commands or direct Kubernetes API calls.
5. This discovery phase focuses on listing Deployments, Secrets, and ServiceAccounts to map available resources, privileges, and service endpoints within the compromised namespace.
6. Based on the gathered intelligence, the adversary plans and executes targeted lateral movement or privilege escalation within the Kubernetes cluster, aiming for the final objective of data exfiltration or cluster control.

## Impact

A successful read of the service account namespace file, while not directly damaging, signifies an adversary's foothold within a Kubernetes pod and their intent to perform further discovery. If left undetected, this reconnaissance can lead to severe consequences, including privilege escalation, lateral movement across the cluster, access to sensitive data stored in secrets, and potentially full cluster compromise. The immediate impact is the loss of confidentiality and integrity for the compromised pod's context, paving the way for broader system compromise and unauthorized resource manipulation or destruction. There are no specific victim counts or sectors identified, as this is a general technique applicable to any Kubernetes deployment.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious file access and process execution.
* Enable `file_event` and `process_creation` logging for Linux containers to activate the detection rules.
* Investigate any alerts from `Kubernetes Service Account Namespace File Read` by building the process tree and shell session timeline around the event to identify parent/child processes and exact commands.
* Correlate Kubernetes audit logs for the affected service account and pod around the timestamp to spot subsequent API calls or enumeration attempts.
* Immediately kill interactive shell processes inside containers (`bash`/`sh` via `kubectl exec`) that trigger this alert, and quarantine the pod/namespace by applying deny-all NetworkPolicy.
* Rotate service account credentials by deleting the pod to force a new projected token, and consider setting `automountServiceAccountToken: false` on workloads where it's not needed.
* Enforce least-privilege RBAC for service accounts, restricting list/get permissions on Secrets, ConfigMaps, and Pods in the namespace.
