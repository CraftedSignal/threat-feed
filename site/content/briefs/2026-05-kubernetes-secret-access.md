---
title: Kubernetes Secret Access by Node or Pod Service Account
slug: 2026-05-kubernetes-secret-access
description: This rule detects Kubernetes audit events where node or pod service accounts are accessing secrets via `get` or `list` operations, which may indicate credential access attempts by attackers sweeping Secret objects for sensitive information.
date: "2026-05-18T09:45:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - credential-access
  - cloud
vendors:
  - Elastic
products:
  - kubernetes
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://attack.mitre.org/techniques/T1552/007/
  - https://kubernetes.io/docs/reference/access-authn-authz/authentication/#service-account-tokens
rules:
  - title: Kubernetes Secret Get or List by Node
    description: Detects Kubernetes Secrets API `get` or `list` requests from node identities (`system:node:*`), which is often a sign of credential access.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - auditd
      - kubernetes
  - title: Kubernetes Secret Get or List by Pod Service Account
    description: Detects Kubernetes Secrets API `get` or `list` requests from pod service accounts (`system:serviceaccount:*`), which may indicate credential access, especially cross-namespace.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - auditd
      - kubernetes
rules_count: 2
---

This detection rule identifies suspicious Kubernetes API access patterns where node components (kubelet) or pod service accounts are directly querying the Kubernetes Secrets API. These identities are typically restricted in their API usage. Attackers might compromise a pod's service account token or node credentials and then attempt to sweep Secret objects to discover credentials, TLS keys, or sensitive application configurations. The rule focuses on `get` or `list` operations against the Secrets API. While legitimate controllers might access secrets, unexpected access patterns from nodes or cross-namespace access from service accounts warrant investigation.

## Attack Chain

1.  An attacker compromises a pod and gains access to its service account token.
2.  Alternatively, an attacker compromises a node and obtains node credentials, allowing them to authenticate with the Kubernetes API.
3.  The attacker uses the compromised service account or node credentials to authenticate to the Kubernetes API.
4.  The attacker attempts to list all secrets in the cluster using `kubectl get secrets --all-namespaces` or similar API calls.
5.  The attacker may target specific secrets by name, attempting to retrieve their contents using `kubectl get secret <secret-name> -n <namespace>`.
6.  The API requests are logged in the Kubernetes audit logs.
7.  The attacker identifies secrets containing sensitive information such as API keys, database credentials, or TLS certificates.
8.  The attacker exfiltrates the sensitive information for use in lateral movement or external attacks.

## Impact

Successful exploitation allows attackers to gain access to sensitive information stored in Kubernetes secrets, such as API keys, database credentials, and TLS certificates. This can lead to further compromise of the cluster, including lateral movement, data exfiltration, and denial-of-service attacks. The rule helps identify unusual access patterns, which can be indicative of malicious activity.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Secret Get or List by Node` to your SIEM and tune for your environment.
*   Deploy the Sigma rule `Kubernetes Secret Get or List by Pod Service Account` to your SIEM and tune for your environment, focusing on cross-namespace access.
*   Review RBAC RoleBindings and ClusterRoleBindings for the affected node or workload to ensure least privilege, as mentioned in the rule description.
*   Investigate source IPs and user agents associated with detected events for anomalous scripts or generic HTTP clients, as described in the rule's triage section.
*   Revoke the compromised token or node credentials and rotate exposed secrets if malicious activity is confirmed, as advised in the response and remediation guidance.
