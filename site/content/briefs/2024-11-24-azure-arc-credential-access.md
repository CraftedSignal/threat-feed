---
title: Azure Service Principal Sign-In Followed by Arc Cluster Credential Access
slug: 2024-11-24-azure-arc-credential-access
description: Detects a service principal authenticating to Azure AD followed by listing credentials for an Azure Arc-connected Kubernetes cluster, indicating potential adversary activity with stolen service principal secrets to establish a proxy tunnel into Kubernetes clusters.
date: "2026-04-10T16:27:52Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - azure
  - azure-arc
  - credential-access
  - initial-access
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/azure/azure-arc/kubernetes/cluster-connect
  - https://learn.microsoft.com/en-us/cli/azure/connectedk8s#az-connectedk8s-proxy
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
  - https://www.ibm.com/think/x-force/identifying-abusing-azure-arc-for-hybrid-escalation-persistence
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
rules:
  - title: Azure Arc - Service Principal Sign-in Followed by List Credentials
    description: Detects a service principal authenticating to Azure AD followed by a request to list credentials for an Azure Arc-connected Kubernetes cluster.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1078.004
      - T1528
    data_sources:
      - activitylogs
      - azure
  - title: Azure - Successful Service Principal Sign-in
    description: Detects successful service principal sign-ins to Azure.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - signinlogs
      - azure
rules_count: 2
---

This detection identifies a specific attack sequence targeting Azure Arc-connected Kubernetes clusters. It focuses on the scenario where a service principal authenticates to Microsoft Entra ID and subsequently requests credentials for an Azure Arc-connected Kubernetes cluster. The `listClusterUserCredential` action is used to retrieve tokens that enable kubectl access through the Arc Cluster Connect proxy. This sequence is particularly concerning when the service principal authenticates externally and immediately accesses Arc cluster credentials, especially from unexpected locations or Autonomous System Numbers (ASNs). This behavior, observed in attacks like those described by IBM X-Force in 2025, can lead to attackers gaining unauthorized access to and control over Kubernetes clusters. Defenders should investigate such events, particularly when the sign-in originates from an unexpected location or ASN.

## Attack Chain

1.  **Initial Compromise:** An attacker gains unauthorized access to a service principal's credentials (e.g., through credential stuffing, phishing, or exposed secrets).
2.  **Service Principal Authentication:** The attacker uses the compromised service principal credentials to authenticate to Microsoft Entra ID (Azure AD) using the `ServicePrincipalSignInLogs`.
3.  **Credential Listing Request:** Immediately following successful authentication, the attacker leverages the service principal to initiate a request to list the cluster user credentials for an Azure Arc-connected Kubernetes cluster, triggering the `MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/LISTCLUSTERUSERCREDENTIAL/ACTION` in the Activity Logs.
4.  **Credential Retrieval:** The attacker retrieves the Arc cluster credentials.
5.  **Proxy Tunnel Establishment:** The attacker uses the retrieved credentials to establish a proxy tunnel into the Kubernetes cluster via the Arc Cluster Connect proxy.
6.  **Kubernetes Access:** With the tunnel established, the attacker can now execute kubectl commands, perform unauthorized actions within the cluster, such as creating, reading, updating, and deleting (CRUD) secrets and configmaps.
7.  **Lateral Movement & Privilege Escalation:** The attacker exploits vulnerabilities or misconfigurations within the Kubernetes cluster to move laterally to other resources, escalate privileges, and gain further control.
8.  **Data Exfiltration or Ransomware Deployment:** The attacker exfiltrates sensitive data from the Kubernetes cluster or deploys ransomware to encrypt critical data, impacting business operations.

## Impact

Successful exploitation of this attack chain can lead to complete compromise of Azure Arc-connected Kubernetes clusters. Attackers can gain unauthorized access to sensitive data, disrupt critical services, and potentially deploy ransomware. The IBM X-Force team has documented cases of attackers using similar techniques for hybrid escalation and persistence. This can impact organizations across all sectors utilizing Azure Arc for managing Kubernetes clusters, potentially affecting dozens or hundreds of clusters per victim organization.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM and tune for your environment to detect the sequence of service principal sign-in followed by Arc cluster credential access.
*   Review Azure AD Audit Logs for recent changes to service principals, focusing on new credentials, federated identities, and owner changes, based on the investigation steps outlined in the rule's note.
*   Enable conditional access policies to restrict service principal authentication by location to prevent logins from unexpected regions, as suggested in the rule's note.
*   Monitor Azure Activity Logs for `MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/LISTCLUSTERUSERCREDENTIAL/ACTION` events to identify potential unauthorized access attempts.
*   Rotate service principal credentials regularly and revoke active sessions and tokens for the SP as outlined in the rule's response and remediation steps.
