---
title: Azure Kubernetes Services (AKS) Kubernetes Pod Deletion
slug: 2024-01-aks-pod-deletion
description: The deletion of Azure Kubernetes Pods can indicate malicious activity aimed at disrupting the environment's normal behavior.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - kubernetes
  - impact
  - cloud
vendors:
  - Microsoft
products:
  - Azure Kubernetes Services
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1529
    technique_name: System Shutdown/Reboot
references:
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
  - https://attack.mitre.org/techniques/T1489/
  - https://attack.mitre.org/techniques/T1529/
rules:
  - title: Azure Kubernetes Pod Deletion
    description: Detects deletion of Azure Kubernetes Pods, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Azure Kubernetes Pod Deletion Failed
    description: Detects failed attempts to delete Azure Kubernetes Pods, potentially indicating reconnaissance or unauthorized access attempts.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

This detection identifies the deletion of Azure Kubernetes Pods, which could indicate malicious activity. Adversaries might delete Kubernetes pods to disrupt services or evade detection. Successful pod deletion operations logged in Azure activity logs are monitored, alerting security teams to potential unauthorized actions impacting environment stability and security. The rule focuses on events logged with the operation name "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE" and a successful outcome. Defenders should be aware of unexpected or unauthorized pod deletions, as these actions can lead to service disruptions and potential data loss. This activity affects Azure Kubernetes Services (AKS) environments.

## Attack Chain

1. An attacker gains unauthorized access to the Azure environment, potentially through compromised credentials or exploiting a vulnerability.
2. The attacker authenticates to the Azure API and identifies the target Kubernetes cluster and namespace.
3. The attacker uses stolen credentials to make an authorized API call.
4. The attacker issues a DELETE request targeting specific pods within the Kubernetes cluster, using the "MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE" operation.
5. Azure processes the deletion request, and if authorized, removes the specified pods from the cluster.
6. The event is logged in Azure Activity Logs with an "Success" outcome.
7. Legitimate applications or services that rely on the deleted pods experience disruption or failure.
8. The attacker achieves their objective, which may include disrupting services, causing data loss, or hindering incident response efforts.

## Impact

Successful pod deletions can lead to service disruptions, application failures, and potential data loss within the Azure Kubernetes Services (AKS) environment. The severity depends on the criticality of the affected pods and the applications they support. A successful attack could impact the availability of customer-facing services, internal business processes, or critical infrastructure components. Undetected malicious pod deletions can also complicate incident response efforts and prolong the time it takes to restore normal operations.

## Recommendation

*   Deploy the Sigma rule `Azure Kubernetes Pod Deletion` to your SIEM and tune for your environment to detect malicious or accidental pod deletions in your Azure environment.
*   Review Azure activity logs for events matching the `MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE` operation name to identify potential pod deletion incidents.
*   Implement stricter access controls and role-based access management to minimize the risk of unauthorized pod deletions.
*   Integrate monitoring and alerting with a SIEM system to detect and respond to unauthorized pod deletions promptly (refer to the setup instructions in the overview).
