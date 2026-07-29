---
title: Kubernetes Service Account Token and Certificate Credential Access
slug: 2026-07-kubernetes-service-account-credential-access
description: A detection rule from Elastic identifies adversaries reading Kubernetes service account tokens or CA certificates within containers, typically using utilities like `cat` on `/var/run/secrets/kubernetes.io/serviceaccount/token` and `ca.crt` to authenticate to the Kubernetes API server and escalate privileges or expand access within the cluster.
date: "2026-07-29T12:33:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - kubernetes
  - credential-access
  - linux
  - elastic-defend
products:
  - Kubernetes
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This rule flags when a container’s service account token or CA certificate is opened, signaling direct access to credentials that grant API permissions within the cluster. Attackers often exec into a running pod, read /var/run/secrets/kubernetes.io/serviceaccount/token and ca.crt, then use the token with kubectl or curl to enumerate namespaces, list secrets, or spawn privileged workloads via the Kubernetes API.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This rule detects the reading of the service account token or certificate inside a container. The service account token or certificate is used to authenticate the container to the Kubernetes API server, and may be used by an adversary to gain access to the Kubernetes API server or other resources within the cluster.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/credential_access_service_account_token_or_cert_read.toml
iocs:
  - type: file_path
    value: /var/run/secrets/kubernetes.io/serviceaccount/token
  - type: file_path
    value: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  - type: file_path
    value: /run/secrets/kubernetes.io/serviceaccount/token
  - type: file_path
    value: /run/secrets/kubernetes.io/serviceaccount/ca.crt
  - type: file_path
    value: /tmp/token
ioc_counts:
  file_path: 5
rules:
  - title: Detect Kubernetes Service Account Token or Certificate File Open
    description: Detects direct file open events for Kubernetes service account tokens or CA certificates within a container, indicating potential credential access.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - credential_access
    techniques:
      - T1005
      - T1552
      - T1552.001
    data_sources:
      - file_event
      - linux
  - title: Detect Utility Execution for Reading Kubernetes Service Account Credentials
    description: Detects common Linux utilities being used to read Kubernetes service account tokens or CA certificates, indicating potential credential access within a container.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - credential_access
    techniques:
      - T1005
      - T1552
      - T1552.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

This Elastic Defend for Containers rule targets malicious activity where adversaries compromise a container and then attempt to extract Kubernetes service account tokens or CA certificates. This activity, observed through file access or process execution, signals an attacker's intent to authenticate to the Kubernetes API server, allowing for privilege escalation, lateral movement, or broader cluster compromise. Attackers typically exec into a running pod, locate files such as `/var/run/secrets/kubernetes.io/serviceaccount/token` and `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`, and then use tools like `cat`, `head`, or `less` to read these sensitive credentials. The goal is to obtain API access, enumerate cluster resources, list secrets, or deploy new, potentially more privileged workloads, posing a significant risk to the entire Kubernetes environment. This rule is designed for Elastic Stack version 9.3.0 and above.

## Attack Chain

1. **Initial Access to Container**: An adversary gains interactive access to a running container, often by `exec`ing into a pod.
2. **Locate Service Account Credentials**: The attacker identifies standard paths for Kubernetes service account credentials, specifically `/var/run/secrets/kubernetes.io/serviceaccount/token` and `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.
3. **Read Credentials**: Using common Linux utilities like `cat`, `head`, `tail`, `more`, `less`, `sed`, or `awk`, the adversary reads the content of the service account token and CA certificate files.
4. **Exfiltrate/Use Token**: The extracted service account token is potentially copied to a temporary location (e.g., `/tmp/token`) or immediately used.
5. **Kubernetes API Authentication**: The adversary utilizes the acquired token to authenticate with the Kubernetes API server, typically via `kubectl` or `curl` commands.
6. **Resource Enumeration**: With API access, the attacker enumerates Kubernetes resources such as namespaces and secrets to gather intelligence about the cluster.
7. **Privilege Escalation / Lateral Movement**: The adversary attempts to list secrets, spawn new pods with elevated privileges, or modify existing workloads to achieve persistence or further compromise the cluster.
8. **Impact**: The attacker achieves arbitrary code execution within the cluster, sensitive data exfiltration, or complete control over Kubernetes resources.

## Impact

If this attack succeeds, adversaries gain unauthorized access to the Kubernetes API server, enabling them to enumerate sensitive resources, list secrets, and spawn privileged workloads. This can lead to a full compromise of the Kubernetes cluster, including data exfiltration, service disruption, and the deployment of malicious software. The potential blast radius extends to all resources accessible by the compromised service account, which can be extensive depending on its RBAC permissions. Organizations face significant operational disruption and data breaches, potentially affecting critical applications and data hosted within the cluster.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment, specifically focusing on process creation and file access logs from Linux containers.
* Monitor for process creation events (`process_creation` log source) in Linux containers where utilities like `cat`, `head`, `tail`, `more`, `less`, `sed`, or `awk` are used to read files under `/var/run/secrets/kubernetes.io/serviceaccount/token` or `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.
* Monitor for file access events (`file_event` log source) on Linux containers targeting `/var/run/secrets/kubernetes.io/serviceaccount/token` or `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.
* Harden Kubernetes deployments by setting `automountServiceAccountToken: false` for pods that do not require API access.
* Implement `kubectl exec/attach` denial policies in production environments via RBAC or admission controllers to prevent adversaries from gaining interactive container shells.
* Regularly review and trim the RBAC permissions of service accounts to adhere to the principle of least privilege, reducing the potential impact of token compromise.
* Respond to detections by immediately deleting the affected pod to invalidate the `/var/run/secrets/kubernetes.io/serviceaccount/token` and scale down the owning Deployment/StatefulSet.
* Kill any interactive shells attached to compromised containers and remove copied credential artifacts such as `/tmp/token` from affected nodes.
