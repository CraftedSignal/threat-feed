---
title: Kubernetes DaemonSet Deployment Detected
slug: 2024-01-kubernetes-daemonset-deployment
description: The creation of a Kubernetes DaemonSet is detected via Kubernetes Audit logs, indicating a potential attempt to maintain persistent access and control within the cluster by ensuring a specific pod runs on every node.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - daemonset
  - persistence
vendors:
  - Kubernetes
  - AWS
products:
  - Kubernetes
  - EKS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
  - https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
  - https://github.com/signalfx/splunk-otel-collector-chart/blob/main/docs/migration-from-sck.md
iocs:
  - type: url
    value: https://github.com/signalfx/splunk-otel-collector-chart/blob/main/docs/migration-from-sck.md
  - type: url
    value: https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
ioc_counts:
  url: 2
rules:
  - title: Kubernetes DaemonSet Created
    description: Detects the creation of a DaemonSet in Kubernetes based on audit logs, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Kubernetes DaemonSet Created (User Agent)
    description: Detects the creation of a DaemonSet in Kubernetes based on audit logs and User Agent, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This brief focuses on the detection of DaemonSet deployments within a Kubernetes cluster. DaemonSets, which ensure a specific pod runs on every node, can be abused by attackers to gain persistent access. The alert triggers upon detecting the creation of a DaemonSet as logged within the Kubernetes Audit logs. This activity is a significant indicator of potentially malicious activity because DaemonSets provide a mechanism for attackers to deploy malicious pods across an entire cluster, enabling persistent attacks, service disruptions, or unauthorized access to sensitive information. The detection logic is based on monitoring Kubernetes API server requests for the creation of DaemonSets and extracting relevant fields, such as user, source IP, and involved resources.

## Attack Chain

1.  Attacker gains initial access to the Kubernetes cluster, potentially through compromised credentials or exploiting a cluster vulnerability.
2.  Attacker authenticates to the Kubernetes API server with sufficient privileges.
3.  Attacker crafts a malicious DaemonSet YAML file, defining the pod to be deployed across all nodes. This could include a container with reverse shell capabilities or data exfiltration tools.
4.  Attacker uses `kubectl` or another API client to submit the DaemonSet creation request to the Kubernetes API server.
5.  The Kubernetes API server validates the request and, if authorized, creates the DaemonSet object. This event is logged in the Kubernetes Audit logs.
6.  The Kubernetes controller manager observes the new DaemonSet and schedules the defined pod on each node in the cluster.
7.  The malicious pod is deployed and starts executing on each node, granting the attacker persistent access and control.
8.  Attacker performs malicious actions from the deployed pods, such as lateral movement, data exfiltration, or denial-of-service attacks.

## Impact

A successful DaemonSet deployment by an attacker can compromise the entire Kubernetes cluster. Every node becomes infected with the malicious pod, providing the attacker with a persistent foothold. This can lead to widespread data exfiltration, denial of service, or the deployment of ransomware across all containerized applications. The blast radius is the entire cluster, potentially impacting all applications running within it.

## Recommendation

*   Enable and properly configure Kubernetes audit logging to capture DaemonSet creation events and other API server activities. Reference the documentation on collecting audit logs from Kubernetes clusters ([https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)).
*   Deploy the provided Sigma rule (`Kubernetes DaemonSet Created`) to detect the creation of DaemonSets based on Kubernetes Audit logs.
*   Investigate any detected DaemonSet creation events, focusing on the user (`user.username`), source IP (`sourceIPs{}`), and the contents of the DaemonSet manifest.
*   For AWS EKS, ensure control plane logging is enabled and that logs are properly ingested into your SIEM. Refer to AWS documentation for enabling EKS control plane logging ([https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html)).
