---
title: Azure Kubernetes Services (AKS) Kubernetes Rolebindings Created
slug: 2024-01-aks-rolebinding-created
description: The creation of role binding or cluster role bindings in Azure Kubernetes Services (AKS) can indicate privilege escalation by an adversary creating a binding to the cluster-admin ClusterRole or other high-privilege roles.
date: "2024-01-02T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - azure
  - kubernetes
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure Kubernetes Services
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
  - https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
rules:
  - title: Detect AKS Role Binding Creation
    description: Detects the creation of Kubernetes RoleBindings or ClusterRoleBindings in Azure Kubernetes Service (AKS) by monitoring Azure Activity Logs.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1098.006
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Detect Valid Accounts used to create AKS Role Bindings
    description: Detects the use of valid accounts to create Kubernetes RoleBindings or ClusterRoleBindings in Azure Kubernetes Service (AKS) which is a potential sign of misuse of the account
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

This detection rule identifies the creation of role binding or cluster role bindings in Azure Kubernetes Services (AKS) by monitoring Azure activity logs for successful creation events. These role bindings assign roles to Kubernetes subjects, like users, groups, or service accounts. An attacker who has permissions to create bindings and cluster-bindings can escalate privileges by creating a binding to the cluster-admin ClusterRole or other high privileges roles. This activity is logged within Azure and can be detected using the Azure Activity Logs. This activity can lead to complete control of the Kubernetes cluster and its resources if a cluster-admin role is bound to a malicious actor.

## Attack Chain

1.  The attacker gains initial access to an Azure account with sufficient permissions to interact with AKS and create role bindings.
2.  The attacker enumerates available roles and cluster roles within the AKS cluster.
3.  The attacker identifies high-privilege roles, such as `cluster-admin`, which would grant extensive control over the cluster.
4.  The attacker creates a new RoleBinding or ClusterRoleBinding, associating the target user/group/service account with the high-privilege role. The Azure activity logs capture this event.
5.  The attacker validates the successful creation of the role binding.
6.  The attacker (or the user/group/service account targeted) leverages the newly granted privileges to perform unauthorized actions within the AKS cluster.
7. The attacker maintains persistence by using the Valid Account (T1078) to access the cluster.

## Impact

Successful exploitation leads to privilege escalation within the AKS cluster, allowing the attacker to perform actions beyond their intended authorization. This can lead to unauthorized access to sensitive data, modification or deletion of critical resources, and potential compromise of the entire Kubernetes environment. While specific victim counts aren't available, the impact is significant for organizations relying on AKS for containerized applications.

## Recommendation

*   Deploy the Sigma rule `Detect AKS Role Binding Creation` to detect the creation of role bindings in your AKS environment by monitoring Azure Activity Logs.
*   Review and tighten Role-Based Access Control (RBAC) policies to ensure that only necessary permissions are granted (reference: description).
*   Investigate any detected role binding creations to validate their legitimacy and identify potential unauthorized privilege escalation attempts (reference: description).
*   Monitor `event.outcome` to ensure the operation was successful and not a failed attempt, which might indicate a misconfiguration or testing (reference: description).
