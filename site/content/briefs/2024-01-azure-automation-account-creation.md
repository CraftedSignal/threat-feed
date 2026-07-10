---
title: Azure Automation Account Creation
slug: 2024-01-azure-automation-account-creation
description: Detect the creation of new Azure Automation accounts, which can be used by attackers for persistence, privilege escalation, and malicious runbook execution within Azure environments.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - automation
  - persistence
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
  - https://docs.microsoft.com/en-us/azure/automation/automation-create-standalone-account?tabs=azureportal
  - https://docs.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker
  - https://www.inversecos.com/2021/12/how-to-detect-malicious-azure.html
  - https://www.netspi.com/blog/technical/cloud-penetration-testing/maintaining-azure-persistence-via-automation-accounts/
  - https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT503/AZT503-3/
  - https://attack.mitre.org/techniques/T1136/003/
rules:
  - title: Azure Automation Account Created
    description: Detects the creation of a new Azure Automation account in Azure Audit logs.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Suspicious Azure Automation Runbook Creation
    description: Detects the creation of an Azure Automation runbook shortly after the Automation Account creation
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

This brief focuses on detecting the creation of new Azure Automation accounts, a technique used by attackers to establish persistence and execute malicious actions within Azure environments. Azure Automation allows users to automate tasks across Azure and on-premise systems via runbooks. An attacker creating a rogue Automation account with elevated privileges can maintain a foothold in the environment, execute malicious scripts, and potentially gain control over virtual machines and other resources. This detection leverages Azure Audit events (Azure Activity log) to identify such suspicious account creation activity. The risk is significant due to the potential for broad impact and the difficulty in tracing actions back to the attacker-controlled Automation account. The provided Splunk analytic was last updated in version 13 on April 15, 2026.

## Attack Chain

1.  The attacker gains initial access to the Azure environment, potentially through compromised credentials or a vulnerability in a web application.
2.  The attacker attempts to create a new Azure Automation account using stolen credentials or through a compromised service principal.
3.  An Azure Audit event is generated with `operationName.value="Microsoft.Automation/automationAccounts/write"` and `status.value=Succeeded`, indicating the successful creation of the account.
4.  The attacker configures the Automation account, assigning it elevated privileges, such as Contributor or Owner roles.
5.  The attacker creates or imports malicious runbooks into the Automation account. These runbooks can contain PowerShell or Python scripts designed to execute malicious tasks.
6.  The attacker leverages the Hybrid Runbook Worker feature to execute runbooks on Azure VMs or on-premise servers, allowing them to move laterally within the environment.
7.  The runbooks execute malicious code, potentially installing backdoors, stealing credentials, or exfiltrating sensitive data.
8.  The attacker maintains persistence by scheduling runbooks to execute regularly, ensuring continued access to the environment.

## Impact

Successful exploitation can lead to significant damage, including data breaches, system compromise, and financial loss. Attackers can leverage Automation accounts to maintain persistence even after initial compromises are remediated. The scope of impact depends on the privileges assigned to the Automation account, but could potentially affect the entire Azure subscription and connected on-premise resources. This could lead to ransomware deployment, sensitive data exfiltration, or long-term espionage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your environment to detect the creation of Azure Automation accounts.
*   Investigate any detected Automation account creation events, focusing on accounts created by unfamiliar users or service principals.
*   Monitor Azure Audit logs for suspicious activity associated with newly created Automation accounts, such as runbook creation and execution.
*   Implement multi-factor authentication (MFA) for all Azure users to reduce the risk of credential compromise.
*   Review and restrict the permissions assigned to Azure Automation accounts, following the principle of least privilege.
*   Use Azure Policy to enforce restrictions on Automation account creation and configuration.
