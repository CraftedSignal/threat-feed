---
title: Azure Kubernetes Events Deleted
slug: 2024-01-azure-kubernetes-events-deleted
description: Adversaries may delete events in Azure Kubernetes to evade detection, which this rule detects via the MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE operation.
date: "2024-01-09T18:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - kubernetes
  - defense-evasion
vendors:
  - Microsoft
products:
  - Azure Kubernetes Service
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
  - https://github.com/elastic/detection-rules/blob/da3852b681cf1a33898b1535892eab1f3a76177a/rules/integrations/azure/defense_evasion_kubernetes_events_deleted.toml
rules:
  - title: Azure Kubernetes Events Deleted
    description: Detects when Events are deleted in Azure Kubernetes. An adversary may delete events in Azure Kubernetes in an attempt to evade detection.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1562.009
    data_sources:
      - azure
      - activitylogs
  - title: Azure Kubernetes Events List Operation
    description: Detects when Events are listed in Azure Kubernetes. This is to detect reconnaissance activity before deletion.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1068
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

Attackers targeting Azure Kubernetes Service (AKS) environments may attempt to remove event logs to cover their tracks and hinder forensic investigations. This activity, which involves deleting Kubernetes events, directly impairs a defender's ability to detect malicious behavior within the cluster. By removing evidence of their actions, attackers can prolong their presence within the environment and increase the potential for further compromise. This technique is relevant for defenders monitoring AKS environments for intrusion activity.

## Attack Chain

1.  The attacker gains initial access to the Azure environment, potentially through compromised credentials or exploiting a vulnerability.
2.  The attacker authenticates to the Azure Kubernetes Service (AKS) cluster with sufficient privileges.
3.  The attacker enumerates existing Kubernetes event logs to identify those they wish to remove.
4.  The attacker executes a command to delete specific Kubernetes events using kubectl or the Azure CLI. The API call used for the deletion is MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE.
5.  The Azure Activity Logs record the event deletion, which is the source of the detection.
6.  The attacker repeats steps 3-4 to remove additional event logs, further obscuring their activities.
7.  The attacker continues with their primary objective, such as deploying malicious containers, exfiltrating data, or establishing persistent access.

## Impact

Successful deletion of Kubernetes events can significantly hinder incident response efforts. Without access to event logs, defenders may struggle to identify the scope and timeline of an attack, potentially leading to incomplete remediation and prolonged exposure. The impact includes increased dwell time for attackers within the compromised environment, as well as a greater likelihood of successful data breaches or system disruptions.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect event deletion activity within AKS environments.
*   Investigate any detected instances of the MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE operation in Azure Activity Logs, as indicated in the rule definition.
*   Implement robust RBAC policies within AKS to minimize the number of users and service accounts with permissions to delete Kubernetes events.
