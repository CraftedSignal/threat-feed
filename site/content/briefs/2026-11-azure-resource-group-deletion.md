---
brief_id: brief-2026-11-03-azure-resource-group-deletion
event_id: brief-2026-11-03-azure-resource-group-deletion
revision: 1
activity_at: "2026-11-03T03:19:20Z"
title: 'Azure Resource Manager: Unauthorized resource group deletion detection'
slug: 2026-11-azure-resource-group-deletion
description: Detection rule identifies potentially destructive Azure resource group deletions by unusual principals using an ES|QL first-seen analysis to distinguish anomalous activity from established CI/CD teardown.
date: "2026-11-03T03:19:20Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Rule provided is functional ES|QL; requires environment-specific tuning.
tags:
  - azure
  - cloud
  - impact
  - defense-evasion
vendors:
  - Microsoft
products:
  - Azure Resource Manager
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Deletion of a resource group is permanent and removes all resources in the group.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
    evidence: Deletion of a resource group is permanent and removes all resources in the group.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Deletion of a resource group is permanent and removes all resources in the group.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1529
    technique_name: System Shutdown/Reboot
    evidence: Deletion of a resource group is permanent and removes all resources in the group.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    evidence: Deletion of a resource group is permanent and removes all resources in the group.
    confidence_band: med
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/impact_resources_resource_group_deletion.toml
  - https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Search for successful resource group deletions by principals with no prior history of similar activity
      technique_id: T1485
      data_needed:
        - Azure Activity Logs (MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The rule utilizes an ES|QL first-seen (new terms) approach keyed on the acting principal so routine infrastructure-as-code teardown is suppressed after the first occurrence.
  mitigation_plan:
    - priority: medium
      action: Apply Azure resource locks (ReadOnly or CanNotDelete) to production-critical resource groups.
      owner: Cloud Engineering
      addresses: T1485
      evidence: Deletion of a resource group is permanent and removes all resources in the group.
---

Azure Resource Group deletion is a permanent operation that removes all contained resources. Attackers may leverage this to perform data destruction, impair recovery by removing snapshots or backups, or cause operational disruption. This detection uses an ES|QL first-seen approach to alert on resource group deletions performed by principals that have not executed this action in the preceding 7 days, helping to filter routine infrastructure-as-code or CI/CD activity while flagging anomalous identity behavior.

## Impact
Deletion of a resource group is irreversible and removes all resources within it. Observed impact can range from authorized environment teardown by automated pipelines to unauthorized destruction of production infrastructure or defensive evasion by clearing logs and supporting resources.

## Recommendation
- Deploy the ES|QL detection logic provided by Elastic to flag first-time resource group deletions.
- Establish a baseline of known CI/CD, IaC, and platform service principals and investigate any alerts triggered by identities outside this scope.
- Implement Azure Policy or management locks on critical production resource groups to prevent accidental or unauthorized deletion.
- Require privileged delete operations to proceed via Privileged Identity Management (PIM) or approved change-control pipelines.
