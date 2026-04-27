---
title: Azure Service Principal Sign-In Followed by Arc Cluster Credential Access
slug: 2024-11-24-azure-arc-credential-access
description: Detects a service principal authenticating to Azure AD followed by listing credentials for an Azure Arc-connected Kubernetes cluster, indicating potential adversary activity with stolen service principal secrets to establish a proxy tunnel into Kubernetes clusters.
date: "2026-04-10T16:27:52Z"
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

This detection identifies a specific attack sequence targeting Azure Arc-connected Kubernetes clusters. It focuses on the scenario where a service principal authenticates to Microsoft Entra ID and subsequently requests credentials for an Azure Arc-connected Kubernetes cluster. The `listClusterUserCredential` action is used to retrieve tokens that enable kubectl access through the Arc Cluster Connect proxy. This sequence is particularly concerning when the service principal authenticates…
