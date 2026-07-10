---
title: Kubectl Secrets Enumeration Across All Namespaces
slug: 2024-01-04-kubectl-secrets-enumeration
description: The use of `kubectl get secrets --all-namespaces` command is detected, which enumerates secret resources across the entire Kubernetes cluster, potentially aiding credential discovery, privilege escalation, or lateral movement.
date: "2024-01-04T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - discovery
  - credential-access
  - kubectl
vendors:
  - Kubernetes
products:
  - Kubernetes
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands#get
  - https://attack.mitre.org/techniques/T1613/
  - https://attack.mitre.org/techniques/T1552/
rules:
  - title: Detect Kubectl Secrets Enumeration
    description: Detects the execution of `kubectl get secrets --all-namespaces` or `kubectl get secrets -A` command to enumerate secrets across all namespaces.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552
      - T1613
    data_sources:
      - process_creation
      - linux
  - title: Detect Kubectl Describe Secrets All Namespaces
    description: Detects the execution of `kubectl describe secrets --all-namespaces` or `kubectl describe secrets -A` command to describe secrets across all namespaces.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The threat involves the execution of the `kubectl get secrets --all-namespaces` command within a Kubernetes environment. This command allows a user to enumerate secret resources across all namespaces in the cluster. Attackers often use this command to identify accessible secrets, which can then be leveraged for credential discovery, privilege escalation, or lateral movement within the cluster. The rule detects the execution of kubectl commands which are querying for secrets across all namespaces. The scope of this activity targets Kubernetes environments running on Linux or macOS. Successful exploitation can lead to unauthorized access to sensitive information stored as Kubernetes secrets.

## Attack Chain

1. An attacker gains initial access to a compromised host within the Kubernetes cluster.
2. The attacker uses `kubectl` to interact with the Kubernetes API.
3. The attacker executes the command `kubectl get secrets --all-namespaces` or `kubectl get secrets -A` to list all secrets across all namespaces.
4. The `kubectl` command queries the Kubernetes API server for secret resources.
5. The API server responds with a list of secrets, including their names, namespaces, and other metadata.
6. The attacker analyzes the output to identify secrets that contain valuable credentials or configuration data.
7. The attacker attempts to access identified secrets to extract sensitive information.
8. The attacker uses the extracted credentials to escalate privileges, move laterally, or compromise other resources within the cluster.

## Impact

A successful attack can lead to the exposure of sensitive information stored in Kubernetes secrets, such as API keys, passwords, and certificates. This exposed information can be used to compromise other applications and services running within the cluster or to gain unauthorized access to external resources. The severity depends on the sensitivity of the exposed secrets and the scope of access they provide. There is no specified victim count or sector targeted in the source.

## Recommendation

*   Deploy the Sigma rule `Detect Kubectl Secrets Enumeration` to your SIEM and tune for your environment to detect the specific command execution.
*   Monitor process execution logs for `kubectl` commands with arguments like `--all-namespaces` or `-A` to identify potential secret enumeration attempts.
*   Implement proper RBAC (Role-Based Access Control) policies to restrict access to secrets and limit the ability of users and service accounts to list secrets across all namespaces.
*   Review Kubernetes audit logs and API activity as described in the rule's triage notes to determine whether any listed secrets were subsequently read, exported, or abused.
