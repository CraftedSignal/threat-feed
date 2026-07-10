---
title: Azure Automation Runbook Created or Modified
slug: 2024-01-azure-automation-runbook-modification
description: An adversary may create or modify an Azure Automation runbook to execute malicious code and maintain persistence in their target's environment, detected through Azure activity logs.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - azure
  - automation
  - runbook
  - execution
  - persistence
vendors:
  - Microsoft
products:
  - Azure Automation
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1648
    technique_name: Serverless Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor
  - https://github.com/hausec/PowerZure
  - https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a
  - https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/
rules:
  - title: Azure Automation Runbook Creation or Modification
    description: Detects when an Azure Automation runbook is created or modified, potentially indicating malicious activity.
    platform: sigma
    severity: low
    tactics:
      - execution
      - persistence
    techniques:
      - T1053
      - T1648
    data_sources:
      - cloudtrail
      - azure
      - azure
  - title: Suspicious Azure Automation Account Activity
    description: Detects potential malicious use of Azure Automation accounts based on unusual activity patterns
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1053
      - T1648
    data_sources:
      - cloudtrail
      - azure
      - azure
rules_count: 2
---

This detection identifies the creation or modification of Azure Automation runbooks, a technique that adversaries can use to execute malicious code within an Azure environment and establish persistence. Azure Automation runbooks are scripts that automate tasks in cloud environments. The activity is detected by monitoring Azure activity logs for specific operations related to runbook creation or modification. While legitimate updates and maintenance may trigger this detection, unauthorized changes to runbooks can introduce backdoors or malicious functionality. The detection focuses on "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE", "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE", or "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION" operations. This activity is a part of exploiting cloud resources for unauthorized purposes.

## Attack Chain

1. Adversary gains initial access to an Azure account with sufficient privileges to manage Automation Accounts.
2. The adversary navigates to the Azure Automation service.
3. The adversary creates a new runbook or modifies an existing one.
4. The runbook is populated with malicious code, such as PowerShell scripts designed to create a backdoor or exfiltrate data.
5. The adversary publishes the runbook, making it active within the Azure environment.
6. The runbook is scheduled to execute automatically or triggered manually.
7. The malicious code within the runbook executes, performing unauthorized actions such as data exfiltration or resource manipulation.
8. The adversary maintains persistence by ensuring the runbook continues to execute on a schedule.

## Impact

A successful attack can lead to unauthorized access to sensitive data, resource hijacking, and persistent backdoors within the Azure environment. The impact ranges from data breaches and service disruption to long-term control of the compromised Azure resources. Even though rated low severity, successful exploitation leads to further malicious actions within the cloud environment, potentially impacting multiple services and data stores.

## Recommendation

*   Deploy the Sigma rule `Azure Automation Runbook Creation or Modification` to your SIEM and tune for your environment to detect suspicious activity (rule).
*   Review Azure activity logs for the `MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE`, `MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE`, and `MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/PUBLISH/ACTION` operations to identify potential unauthorized changes (logs).
*   Implement strict access controls and multi-factor authentication for Azure accounts with permissions to manage Automation Accounts (best practice).
*   Regularly audit and review the content of Azure Automation runbooks to identify any unauthorized or suspicious code (best practice).
*   Consider enabling logging of runbook execution to gain deeper visibility into their activity (best practice).
