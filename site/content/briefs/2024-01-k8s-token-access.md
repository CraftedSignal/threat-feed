---
title: Kubernetes Service Account Token Access Followed by API Request
slug: 2024-01-k8s-token-access
description: Detection of interactive access to a Kubernetes service account token or certificate followed by a Kubernetes API request, potentially indicating credential theft and lateral movement within the cluster.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - credential-access
  - lateral-movement
  - container
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/execution_d4c_k8s_mda_service_account_token_access_followed_by_kubernetes_api_request.toml
rules:
  - title: K8s Service Account Token Access Followed by API Request
    description: Detects access to service account token or certificate followed by kubernetes API request indicating potential credential access and lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - lateral_movement
    techniques:
      - T1550
      - T1552
    data_sources:
      - file_event
      - linux
  - title: K8s API request after file access
    description: Detect a kubernetes API request shortly after a file was accessed in a container
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1613
    data_sources:
      - kubernetes
      - audit_logs
rules_count: 2
---

This threat brief focuses on detecting malicious activity within Kubernetes environments where an attacker gains unauthorized access to service account tokens or certificates and subsequently uses these credentials to make API requests. This activity, often seen after initial container compromise, allows attackers to enumerate resources, escalate privileges, and move laterally within the cluster. The detection is based on a combination of Defend for Containers and Kubernetes audit logs, correlating interactive file access to service account credentials with near-immediate API requests. This technique is relevant for defenders as it highlights a common path for attackers to expand their foothold after compromising an initial container, and potentially pivot to other nodes or services. This activity has been observed in production environments, and is detectable using Elastic Stack version 9.3.0 and later, due to the reintroduction of Defend for Containers integration.

## Attack Chain

1. An attacker gains initial access to a container within a Kubernetes pod, possibly through exploiting a vulnerability in the application running inside the container.
2. The attacker executes a shell within the container using `kubectl exec` or similar methods, establishing an interactive session.
3. The attacker accesses the service account token and/or CA certificate located at `/var/run/secrets/kubernetes.io/serviceaccount/token` and `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.
4. The attacker uses `curl` or `kubectl` with the stolen token and CA certificate to interact with the Kubernetes API server.
5. The attacker enumerates the cluster resources, such as listing pods (`kubectl get pods`), secrets (`kubectl get secrets`), or other sensitive information.
6. The attacker attempts to escalate privileges by creating privileged pods or modifying RBAC roles.
7. The attacker moves laterally within the cluster by leveraging the stolen credentials to access other services or nodes.
8. The attacker's final objective can vary but commonly includes data exfiltration, deployment of malicious workloads, or further exploitation of the environment.

## Impact

Successful exploitation can lead to complete compromise of the Kubernetes cluster, including unauthorized access to sensitive data, deployment of malicious containers, and denial of service. Depending on the RBAC permissions associated with the compromised service account, the attacker could potentially gain control over the entire cluster. Organizations using vulnerable Kubernetes deployments are at risk, with potential consequences including data breaches, service disruptions, and reputational damage.

## Recommendation

*   Deploy the Sigma rule "K8s Service Account Token Access Followed by API Request" to your SIEM, tuning the `maxspan` value based on your environment.
*   Enable both `cloud_defend.file` and `kubernetes.audit_logs` log sources to collect the necessary data for this detection (Elastic Stack).
*   Harden Kubernetes deployments by disabling `automountServiceAccountToken` on pods that do not require it (Kubernetes documentation).
*   Implement least-privilege RBAC to limit the permissions of service accounts (Kubernetes documentation).
*   Monitor network egress from pods for suspicious connections to external destinations, correlating with service account token access (Network monitoring tools).
*   Enforce Pod Security Admission to block privileged/interactive shells, restricting exec/attach via RBAC or admission policies (Kubernetes documentation).
