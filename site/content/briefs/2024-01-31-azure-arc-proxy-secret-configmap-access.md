---
title: Kubernetes Secret or ConfigMap Access via Azure Arc Proxy
slug: 2024-01-31-azure-arc-proxy-secret-configmap-access
description: Detection of unauthorized access to Kubernetes secrets or configmaps via the Azure Arc AAD proxy service account, indicating potential abuse of stolen service principal credentials to read, exfiltrate, or modify sensitive data.
date: "2024-01-31T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - azure-arc
  - credential-access
  - collection
vendors:
  - Microsoft
products:
  - Azure Arc
  - Kubernetes
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
references:
  - https://learn.microsoft.com/en-us/azure/azure-arc/kubernetes/cluster-connect
  - https://microsoft.github.io/Threat-Matrix-for-Kubernetes/
  - https://www.ibm.com/think/x-force/identifying-abusing-azure-arc-for-hybrid-escalation-persistence
  - https://cloud.google.com/blog/topics/threat-intelligence/escalating-privileges-azure-kubernetes-services
  - https://www.wiz.io/blog/lateral-movement-risks-in-the-cloud-and-how-to-prevent-them-part-3-from-compromis
rules:
  - title: Kubernetes Secret or ConfigMap Access via Azure Arc Proxy
    description: Detects access to Kubernetes secrets or configmaps by the Azure Arc proxy service account, excluding system namespaces.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - credential_access
    techniques:
      - T1552.007
    data_sources:
      - auditd
      - kubernetes
  - title: Kubernetes Impersonated User Activity via Azure Arc
    description: Detects specific verbs performed by impersonated users through the Azure Arc proxy, focusing on potentially malicious actions.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - auditd
      - kubernetes
rules_count: 2
---

This detection rule identifies suspicious access patterns within Kubernetes clusters connected to Azure Arc. Specifically, it focuses on activity where secrets or configmaps are accessed, created, modified, or deleted, and the Kubernetes audit logs indicate the Azure Arc AAD proxy service account (`system:serviceaccount:azure-arc:azure-arc-kube-aad-proxy-sa`) as the user. The `impersonatedUser` field contains the actual caller identity, suggesting operations are being routed through the Azure ARM API, rather than directly via `kubectl`.  While Azure Arc-managed workflows legitimately use this proxy, adversaries with compromised service principal credentials can exploit Arc Cluster Connect. This allows them to read, exfiltrate, or modify secrets and configmaps while masking their activity under the guise of the Arc proxy service account in K8s audit logs. The rule excludes known Arc namespaces and Helm release secrets to reduce false positives.

## Attack Chain

1. An attacker compromises an Azure AD service principal with permissions to interact with the Azure Arc-connected Kubernetes cluster.
2. The attacker authenticates to Azure using the compromised service principal credentials.
3. The attacker leverages the Azure ARM API to issue commands targeting the Kubernetes cluster, specifically secrets or configmaps. This might involve using `LISTCLUSTERUSERCREDENTIAL` to initiate an Arc proxy session.
4. The Azure Arc Cluster Connect proxy receives the request and impersonates the requesting user.
5. The proxy service account (`system:serviceaccount:azure-arc:azure-arc-kube-aad-proxy-sa`) in the Kubernetes cluster executes the requested operation (get, list, create, update, patch, or delete) against secrets or configmaps.
6. Kubernetes audit logs record the activity, showing the Arc proxy service account as the user and the attacker's identity in the `impersonatedUser` field.
7. The attacker potentially retrieves sensitive data from secrets (e.g., database credentials, API keys) or configmaps.
8. The attacker exfiltrates the retrieved data or uses it to further compromise the Kubernetes cluster or connected resources.

## Impact

Successful exploitation allows attackers to gain unauthorized access to sensitive information stored in Kubernetes secrets and configmaps. This can lead to data breaches, lateral movement within the cluster, and further compromise of the overall cloud environment.  The impact depends on the data stored in the compromised secrets and configmaps, but it could include exposure of database credentials, API keys, or other sensitive configuration data.  Compromised credentials can then be used to access other systems and resources, expanding the scope of the attack.

## Recommendation

*   Deploy the Sigma rule `Kubernetes Secret or ConfigMap Access via Azure Arc Proxy` to your SIEM and tune for your environment.
*   Investigate any alerts generated by the Sigma rule by examining the `kubernetes.audit.impersonatedUser.username` field to identify the actual caller and correlating with Azure Activity Logs.
*   Regularly review and audit Azure AD service principals with permissions to access Azure Arc-connected Kubernetes clusters.
*   Monitor Azure Sign-In Logs for suspicious authentication activity related to service principals used for Azure Arc management.
*   Consider implementing stricter network segmentation to limit the blast radius of compromised service principals.
