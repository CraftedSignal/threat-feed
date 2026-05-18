---
title: Kubectl Secrets Enumeration Across All Namespaces
slug: 2026-05-kubectl-secrets-enumeration
description: The rule detects the use of the 'kubectl get secrets --all-namespaces' command, which enumerates secret resources across the entire Kubernetes cluster, potentially aiding credential discovery, privilege escalation, or lateral movement by attackers.
date: "2026-05-18T09:44:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kubernetes
  - container
  - discovery
  - credential-access
vendors:
  - Elastic
products:
  - Elastic Defend
  - Elastic Endgame
affected_os:
  - Linux
  - macOS
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
rules:
  - title: Detect Kubectl Secrets Enumeration Across All Namespaces
    description: Detects the use of kubectl to enumerate secrets across all namespaces which can indicate reconnaissance activity.
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
  - title: Detect Kubectl Secrets Enumeration Across All Namespaces (MacOS)
    description: Detects the use of kubectl to enumerate secrets across all namespaces on macOS, which can indicate reconnaissance activity.
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
      - macos
rules_count: 2
---

This detection rule identifies the use of the `kubectl get secrets --all-namespaces` command, or its shorthand `-A`, which can be used to enumerate secret resources across a Kubernetes cluster. Attackers may leverage this command to discover accessible secrets in multiple namespaces. This information can be used to gain unauthorized access to credentials, escalate privileges, or move laterally within the cluster. The rule focuses on monitoring kubectl executions that request secrets from all namespaces, allowing defenders to detect broad secret discovery activity. This is especially important in environments where least privilege principles are not strictly enforced, and excessive permissions are granted to users or service accounts.

## Attack Chain

1. An attacker gains initial access to a compromised host within the Kubernetes cluster.
2. The attacker executes the `kubectl` command-line tool.
3. The attacker uses the `get secrets` command with the `--all-namespaces` or `-A` flag to enumerate all secrets in all namespaces.
4. The `kubectl` tool queries the Kubernetes API server for secret resources across all namespaces.
5. The API server responds with a list of secrets, including their names and namespaces.
6. The attacker parses the output to identify potentially valuable secrets.
7. The attacker attempts to access the identified secrets to retrieve sensitive information such as credentials, tokens, or API keys.
8. The attacker uses the extracted credentials to escalate privileges, move laterally to other parts of the cluster, or access external resources.

## Impact

Successful execution of this attack chain can lead to the exposure of sensitive credentials stored as Kubernetes secrets. This may allow attackers to gain unauthorized access to critical systems, escalate privileges within the cluster, or move laterally to other environments. A wide range of sectors employing Kubernetes for orchestration are vulnerable, including tech companies, financial institutions, and government organizations.

## Recommendation

*   Deploy the Sigma rule "Detect Kubectl Secrets Enumeration Across All Namespaces" to your SIEM and tune for your environment.
*   Review the full process command line to confirm whether the command used "get secrets --all-namespaces" or the short form "-A", and determine whether additional output modifiers such as "-o yaml" or "-o json" were used, as described in the rule's note section.
*   Validate whether the user or service account that executed the command should have cluster-wide visibility into secrets, and revoke or reduce permissions if the access is not justified, as per the rule's note section.
*   Enable Elastic Defend integration to collect the necessary process execution data. Follow the setup steps outlined in the rule setup section.
