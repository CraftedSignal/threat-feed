---
title: Azure Automation Runbook Deleted
slug: 2024-01-11-azure-automation-runbook-deleted
description: Detection of Azure Automation runbook deletion, potentially indicating defense evasion or disruption of automated business processes by an adversary removing malicious or critical runbooks.
date: "2024-01-11T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - azure
  - defense-evasion
  - impact
vendors:
  - Microsoft
products:
  - Azure Automation
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor
  - https://github.com/hausec/PowerZure
  - https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a
  - https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/
rules:
  - title: Azure Automation Runbook Deleted
    description: Detects the deletion of Azure Automation runbooks, which could indicate defense evasion or disruption of automated processes.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - azure
  - title: Azure Automation Account Activity - Runbook Deletion by Unusual User
    description: Detects runbook deletions by accounts not typically associated with automation tasks, potentially indicating unauthorized activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

This detection identifies when an Azure Automation runbook is deleted. Azure Automation runbooks are used to automate repetitive tasks and manage cloud resources. An adversary may delete an Azure Automation runbook to disrupt normal automated business operations or to remove a malicious runbook they previously deployed, thus covering their tracks. The detection focuses on monitoring Azure activity logs for events indicating the successful deletion of runbooks. While often legitimate, unexpected or unauthorized runbook deletions warrant investigation, especially in sensitive environments. The rule is designed to work with data ingested through the Azure Fleet integration or Filebeat module, which provides the necessary Azure activity logs.

## Attack Chain

1. An adversary gains initial access to an Azure account, potentially through compromised credentials or exploiting a vulnerability in the Azure environment.
2. The attacker identifies Azure Automation accounts and their associated runbooks.
3. If the attacker previously created a malicious runbook for persistence or other malicious purposes, they may delete it to evade detection.
4. Alternatively, the attacker may delete legitimate runbooks to disrupt automated processes and cause operational impact.
5. The attacker executes the runbook deletion command, triggering an event logged in the Azure activity logs. The specific operation name is "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DELETE".
6. The Azure platform records the deletion event, including the user identity and timestamp of the action.
7. If successful, the runbook is permanently removed from the automation account.
8. The deletion leads to disruption of the automated tasks previously performed by the runbook, potentially impacting business operations or security measures.

## Impact

Successful deletion of Azure Automation runbooks can lead to the disruption of critical automated tasks, affecting business operations and potentially causing financial or reputational damage. The severity depends on the importance of the deleted runbooks. If malicious runbooks are deleted, it serves as defense evasion, potentially delaying incident response.

## Recommendation

*   Deploy the Sigma rule provided below to your SIEM to detect Azure Automation runbook deletions and tune it for your environment.
*   Investigate any detected runbook deletions, focusing on the user identity and context of the event (refer to the investigation steps in the rule description).
*   Implement stricter access controls and auditing for Azure Automation accounts to limit the ability to delete runbooks to authorized personnel.
*   Consider enabling versioning or backups of Azure Automation runbooks to facilitate restoration in case of accidental or malicious deletion.
*   Monitor user accounts for suspicious activity prior to the deletion event, such as privilege escalation or unusual access patterns.
