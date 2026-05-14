---
title: Kubernetes API Server Proxying Request to Kubelet
slug: 2026-05-kubernetes-api-proxy-kubelet
description: Detection of non-system identities using the Kubernetes nodes/proxy API to proxy requests through the API server directly to a node's Kubelet, potentially leading to privilege escalation and sensitive information exposure.
date: "2026-05-14T14:13:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - privilege-escalation
  - lateral-movement
  - discovery
vendors:
  - kubernetes
products:
  - kubernetes
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
references:
  - https://kubernetes.io/docs/concepts/cluster-administration/proxies/
  - https://attack.mitre.org/techniques/T1552/007/
rules:
  - title: Kubernetes API Server Proxying Request to Kubelet
    description: Detects non-system identities using the Kubernetes nodes/proxy API to proxy requests through the API server directly to a node's Kubelet.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - lateral_movement
      - privilege_escalation
    techniques:
      - T1550
      - T1550.001
      - T1611
      - T1613
    data_sources:
      - webserver
  - title: Kubernetes API Server Proxying Request to Kubelet - Exec/Run
    description: Detects non-system identities using the Kubernetes nodes/proxy API to execute commands in pods by proxying requests through the API server directly to a node's Kubelet.
    platform: sigma
    severity: high
    tactics:
      - lateral_movement
      - privilege_escalation
    techniques:
      - T1550
      - T1550.001
      - T1611
    data_sources:
      - webserver
rules_count: 2
---

This detection rule identifies instances where non-system identities are leveraging the Kubernetes nodes/proxy API to proxy requests directly to a node's Kubelet. This bypasses the need for direct network access or Kubelet TLS certificates. By exploiting this proxy path, an attacker can gain unauthorized access to sensitive information and perform malicious activities on worker nodes. This can lead to the enumeration of pod specifications, including environment variable secrets, the retrieval of Kubelet configuration and PKI material, the harvesting of container logs, and potentially executing commands inside containers. The rule excludes common monitoring endpoints (/metrics, /healthz, /stats) to reduce false positives from legitimate observability tooling. This activity can be used for privilege escalation and lateral movement within the Kubernetes cluster.

## Attack Chain

1. An attacker compromises a user or service account within the Kubernetes cluster.
2. The attacker identifies that the compromised identity has `nodes/proxy` RBAC permissions.
3. The attacker crafts a request to the Kubernetes API server, targeting the `/proxy` subresource of a node.
4. The API server proxies the request to the Kubelet on the specified node without requiring direct network access to the Kubelet.
5. The attacker enumerates pod specifications, including sensitive environment variables, using the `/proxy/pods` endpoint.
6. The attacker retrieves Kubelet configuration and authentication settings via the `/proxy/configz` endpoint.
7. The attacker attempts to execute commands inside containers via `/proxy/exec` or `/proxy/run`.
8. The attacker leverages the exposed Kubelet API to gain elevated privileges or move laterally within the cluster.

## Impact

Successful exploitation allows attackers to list all pod specifications, including environment variable secrets, read Kubelet configuration and PKI material, retrieve container logs, and potentially execute commands inside containers across all workloads on the target node. The risk score is rated at 47, and the severity is classified as medium. If environment variables are accessed, all credentials, API keys and database passwords may be compromised. If commands are executed on a container, the target node must be considered fully compromised.

## Recommendation

*   Deploy the Sigma rule "Kubernetes API Server Proxying Request to Kubelet" to your SIEM and tune for your environment to detect unauthorized access to the Kubelet API.
*   Review RBAC roles granting `nodes/proxy` permission and remove any unauthorized bindings, as detailed in the overview.
*   If `/proxy/pods` was accessed, rotate all affected credentials, API keys, and database passwords.
*   Audit all ClusterRoles for `nodes/proxy` permission and restrict access to only infrastructure automation accounts.
*   Monitor `kubernetes.audit.requestURI` to identify which Kubelet endpoint was proxied to determine attacker intent.
