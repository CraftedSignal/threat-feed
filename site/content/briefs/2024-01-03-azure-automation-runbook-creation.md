---
title: Azure Automation Runbook Creation for Persistence
slug: 2024-01-03-azure-automation-runbook-creation
description: This analytic detects the creation of a new Azure Automation Runbook within an Azure tenant using Azure Audit events, which adversaries with privileged access can abuse to maintain persistence, escalate privileges, or execute malicious code, potentially leading to unauthorized actions and compromise of the Azure environment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - persistence
  - automation
  - cloud
vendors:
  - Microsoft
products:
  - Azure Automation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://docs.microsoft.com/en-us/azure/automation/overview
  - https://docs.microsoft.com/en-us/azure/automation/automation-runbook-types
  - https://www.inversecos.com/2021/12/how-to-detect-malicious-azure.html
  - https://www.netspi.com/blog/technical/cloud-penetration-testing/maintaining-azure-persistence-via-automation-accounts/
  - https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT503/AZT503-3/
  - https://attack.mitre.org/techniques/T1136/003/
rules:
  - title: Azure Automation Runbook Created
    description: Detects the creation of new Azure Automation Runbooks, which can be used for persistence and privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - cloudtrail
      - azure
      - auditlog
  - title: Suspicious Azure Automation Account Creation
    description: Detects the creation of an Azure Automation account by an unusual user
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - cloudtrail
      - azure
      - auditlog
rules_count: 2
---

The creation of Azure Automation Runbooks can be a legitimate administrative task, but it also presents a significant security risk. Threat actors with sufficient privileges can create or modify runbooks to establish persistence, escalate privileges, or execute malicious code within the Azure environment. This activity, if malicious, can lead to significant damage, including the creation of rogue Global Administrators, unauthorized code execution on virtual machines, and ultimately, the compromise of the entire Azure infrastructure. This brief focuses on detecting the creation of these runbooks as a potential indicator of malicious activity and provides guidance on how to identify and respond to such events. The detection logic is based on Azure Audit events.

## Attack Chain

1. An attacker gains initial access to an Azure tenant, possibly through compromised credentials or exploiting a vulnerability.
2. The attacker escalates their privileges to a level sufficient to create or modify Azure Automation Runbooks.
3. The attacker creates a new Azure Automation Account if one does not already exist, or uses an existing one.
4. The attacker crafts a malicious Runbook containing code designed to perform unauthorized actions. This could involve PowerShell scripts or other supported languages.
5. The attacker creates the malicious Azure Automation Runbook, triggering an Azure Audit event with `operationName.value="Microsoft.Automation/automationAccounts/runbooks/write"`.
6. The attacker schedules or manually executes the Runbook.
7. The Runbook executes malicious code, potentially creating new user accounts with elevated privileges or deploying malware to virtual machines.
8. The attacker achieves persistence by maintaining the Runbook for future unauthorized access or control.

## Impact

Successful exploitation via malicious Azure Automation Runbook creation can lead to a complete compromise of the Azure environment. Attackers can create new administrative accounts, giving them persistent and unrestricted access. They can execute arbitrary code on virtual machines, potentially leading to data theft, ransomware deployment, or other destructive activities. The impact can range from data breaches and service disruptions to significant financial losses and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Azure Automation Runbook Created` to your SIEM to detect suspicious runbook creation activity. Tune the rule based on your environment to minimize false positives.
*   Investigate any detected instances of Runbook creation, paying close attention to the user involved (`user` field) and the contents of the Runbook itself.
*   Monitor Azure Audit logs for unusual or unauthorized activity related to Automation Accounts and Runbooks.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges, to mitigate the risk of credential compromise.
*   Review and enforce the principle of least privilege, ensuring that users only have the necessary permissions to perform their tasks.
