---
title: Kubernetes Static Pod Manifest File Access
slug: 2026-06-kubernetes-static-pod-manifest-access
description: This rule detects Linux process executions that reference /etc/kubernetes/manifests in process arguments, which may indicate tampering with static pod manifests for persistence or privilege escalation in Kubernetes environments.
date: "2026-06-01T10:10:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - container
  - persistence
  - privilege-escalation
  - linux
vendors:
  - Elastic
  - Kubernetes
products:
  - Elastic Defend
  - Auditd Manager
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://kubernetes.io/docs/tasks/configure-pod-container/static-pod/
  - https://attack.mitre.org/techniques/T1053/007/
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1543/
  - https://attack.mitre.org/techniques/T1543/005/
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_kubernetes_static_pod_manifest_path_process_execution.toml
rules:
  - title: Kubernetes Static Pod Manifest File Access (Shell)
    description: Detects Linux process executions where shells reference /etc/kubernetes/manifests in process arguments, which indicates tampering with manifests for persistence or privileged workload placement.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1053.007
      - T1543.005
    data_sources:
      - process_creation
      - linux
  - title: Kubernetes Static Pod Manifest File Access (Editors/Utilities)
    description: Detects Linux process executions where editors or file utilities reference /etc/kubernetes/manifests in process arguments, indicating potential tampering with manifests.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1053.007
      - T1543.005
    data_sources:
      - process_creation
      - linux
  - title: Kubernetes Static Pod Manifest File Access (Downloaders)
    description: Detects Linux process executions where downloaders reference /etc/kubernetes/manifests in process arguments, indicating potential retrieval of malicious manifests.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1053.007
      - T1543.005
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

This detection rule identifies suspicious process executions on Linux systems that interact with Kubernetes static pod manifest files located in `/etc/kubernetes/manifests`. Static pods are managed directly by the kubelet daemon on each node, and any modifications to their manifest files can lead to persistent changes in the cluster state or elevation of privileges. The rule focuses on detecting the use of shells, editors, interpreters, or file manipulation utilities that reference this directory within their process arguments, suggesting potential unauthorized staging or tampering with these critical manifest files. This activity can allow attackers to deploy malicious pods, alter existing workloads, or gain persistent access to the Kubernetes cluster. The rule is designed to complement file-telemetry rules that directly monitor the creation or modification of manifest files themselves.

## Attack Chain

1.  An attacker gains initial access to a Kubernetes node, potentially through compromised credentials or an exploited vulnerability.
2.  The attacker identifies the location of static pod manifests in `/etc/kubernetes/manifests`.
3.  The attacker uses a shell (e.g., `bash`, `sh`) or a text editor (e.g., `vi`, `nano`) to view the contents of a manifest file.
4.  The attacker modifies an existing manifest file or creates a new one to deploy a malicious pod. This may involve using utilities like `echo`, `tee`, or `dd` to write the new manifest to disk.
5.  The attacker uses scripting runtimes like python, perl, or ruby to automate the manifest modification process or to download malicious manifests.
6.  The attacker uses utilities like `curl`, `wget`, or `scp` to download a malicious manifest from an external source and save it to `/etc/kubernetes/manifests`.
7.  The kubelet automatically detects the change in the manifest directory and deploys or updates the static pod accordingly.
8.  The malicious pod executes, granting the attacker persistent access or elevated privileges within the Kubernetes cluster.

## Impact

Successful exploitation can allow attackers to gain persistent access to the Kubernetes cluster by deploying malicious static pods. This can lead to the compromise of sensitive data, disruption of services, or further escalation of privileges within the cluster. The number of victims and targeted sectors depends on the scope of the compromised Kubernetes environment.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect suspicious process executions referencing `/etc/kubernetes/manifests`.
*   Enable Elastic Defend or configure Auditd Manager with process telemetry and command-line argument capture to provide the necessary data for detection.
*   Baseline approved automation and interactive admin sessions on control plane nodes to reduce false positives, as mentioned in the rule's `false_positives` section.
*   Correlate detected events with Kubernetes audit logs and node/agent telemetry for related compromise indicators, as suggested in the rule's `note` section.
*   If unauthorized activity is detected, restore manifests from known-good sources, isolate the affected host, and review cluster integrity per incident response policy.
