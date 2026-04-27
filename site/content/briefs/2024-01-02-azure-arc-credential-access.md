---
title: Azure Service Principal Sign-In Followed by Arc Cluster Credential Access
slug: 2024-01-02-azure-arc-credential-access
description: Detects a service principal authenticating to Microsoft Entra ID and then listing credentials for an Azure Arc-connected Kubernetes cluster within a short time window, indicating potential unauthorized access to Kubernetes clusters via stolen service principal secrets.
date: "2026-03-17T15:06:47Z"
severities:
  - medium
tags:
  - azure
  - azure-arc
  - credential-access
  - initial-access
mitre_ttps:
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
  - title: Azure Service Principal Sign-In and Arc Credential Access
    description: Detects a service principal authenticating to Azure and then listing credentials for an Azure Arc-connected Kubernetes cluster.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1078.004
      - T1552.007
    data_sources:
      - activitylogs
      - azure
  - title: Suspicious Azure Arc Credential Listing
    description: Detects access to Azure Arc cluster credentials by a service principal outside of normal business hours or from unexpected locations.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - activitylogs
      - azure
rules_count: 2
---

This detection rule identifies a specific attack chain targeting Azure Arc-connected Kubernetes clusters. The attack begins with a service principal authenticating to Microsoft Entra ID and immediately requesting credentials for an Azure Arc-connected Kubernetes cluster. This `listClusterUserCredential` action retrieves tokens enabling `kubectl` access via the Arc Cluster Connect proxy. This behavior is indicative of adversaries using stolen service principal secrets to gain unauthorized access…
