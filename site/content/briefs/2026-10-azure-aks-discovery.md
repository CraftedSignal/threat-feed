---
brief_id: brief-2026-10-21-azure-aks-discovery
event_id: brief-2026-10-21-azure-aks-discovery
revision: 1
activity_at: "2026-10-21T13:59:01Z"
title: 'Azure Kubernetes Service: Multi-resource discovery detection'
slug: 2026-10-azure-aks-discovery
description: This detection identifies potential reconnaissance activity in Azure Kubernetes Service (AKS) by flagging identities that enumerate three or more distinct Kubernetes API resource types within a short timeframe.
date: "2026-10-21T13:59:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic provided by source as production-ready ESQL.
cpes:
  - cpe:2.3:a:microsoft:azure_kubernetes_service:*:*:*:*:*:*:*:*
tags:
  - cloud
  - kubernetes
  - azure
  - discovery
  - monitoring
vendors:
  - Microsoft
products:
  - Azure Kubernetes Service
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: Detects an AKS (Azure Kubernetes Service) identity that lists or gets multiple distinct Kubernetes API resource types associated with cluster orientation.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/discovery_azure_aks_multi_resource_discovery.toml
  - https://microsoft.github.io/Threat-Matrix-for-Kubernetes/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable AKS diagnostic log collection for kube-audit category
      owner: IT Operations
      due: 48h
      evidence: AKS kube-audit events are required to populate the ESQL fields used by this rule.
  hunt_leads:
    - lead: Identify identities performing cross-namespace listings or cluster-scoped resource enumeration
      technique_id: T1613
      data_needed:
        - kube-audit logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Unexpected enumeration of nodes, clusterroles, or serviceaccounts indicates reconnaissance.
---

This rule monitors Azure Kubernetes Service (AKS) `kube-audit` logs to identify reconnaissance behavior. It specifically tracks identities that access multiple Kubernetes API resource types - such as namespaces, nodes, pods, roles, clusterroles, configmaps, serviceaccounts, rolebindings, and clusterrolebindings - within a single window. By focusing on the cardinality of unique resources accessed, the logic differentiates cluster orientation and reconnaissance from steady-state controllers or platform-managed identities.

## Impact

Successful reconnaissance allows an adversary to map the cluster environment, identify high-value targets, and understand RBAC structures, which are critical precursors to privilege escalation or lateral movement within the containerized environment.

## Recommendation

- Deploy the provided Elastic ESQL detection rule to identify anomalous multi-resource enumeration in AKS clusters.
- Establish a baseline of legitimate CI/CD, GitOps, and backup operations to exclude expected service account activity and reduce false positives.
- Review the identities (`Esql.username`) and user agents (`Esql.user_agent`) identified by this rule for potential credential compromise, especially those involving `kubectl`.
- Ensure AKS diagnostic logs, specifically the `kube-audit` category, are correctly routed through Event Hubs to the monitoring environment.
