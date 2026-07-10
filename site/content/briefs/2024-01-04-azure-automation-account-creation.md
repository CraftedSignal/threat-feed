---
title: Suspicious Azure Automation Account Creation
slug: 2024-01-04-azure-automation-account-creation
description: An adversary may create an Azure Automation account to maintain persistence in the target environment by automating malicious tasks.
date: "2024-01-04T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - persistence
  - cloud
vendors:
  - Microsoft
products:
  - Azure Automation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor
  - https://github.com/hausec/PowerZure
  - https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a
  - https://azure.microsoft.com/en-in/blog/azure-automation-runbook-management/
rules:
  - title: Azure Automation Account Created
    description: Detects the creation of an Azure Automation Account, which can be used for persistence.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Suspicious Azure Automation Account Permissions
    description: Detects when an Azure Automation account is granted elevated privileges, such as Contributor or Owner roles, which could be indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

Azure Automation accounts allow users to automate management tasks and orchestrate actions across systems. An attacker may create an Automation Account for persistence, defense evasion, or lateral movement. The primary technique involves creating a valid account (T1078) within the Azure environment and abusing it for malicious purposes. This activity can be difficult to detect because the creation of Automation Accounts is a legitimate administrative function. Defenders need to monitor these events and correlate them with other suspicious activities. This brief focuses on detecting the initial creation of such accounts, providing a starting point for deeper investigation.

## Attack Chain

1. The attacker gains initial access to the Azure environment, possibly through compromised credentials or a misconfigured service principal.
2. The attacker authenticates to the Azure Resource Manager API.
3. The attacker uses the Azure CLI or PowerShell module to create a new Azure Automation account using the `New-AzAutomationAccount` command or equivalent API call.
4. The attacker configures the Automation Account with necessary permissions, possibly granting it access to other resources within the environment.
5. The attacker creates Runbooks within the Automation Account that contain malicious scripts designed to perform tasks such as data exfiltration, lateral movement, or privilege escalation.
6. The attacker schedules the Runbooks to execute automatically or triggers them manually as needed to maintain persistence.
7. The attacker uses the Automation Account to maintain a foothold in the environment, bypassing traditional security controls and remaining undetected for extended periods.
8. The attacker leverages the compromised Automation Account to achieve their final objective, such as data theft, system compromise, or disruption of services.

## Impact

A successful attack can lead to long-term persistence within the Azure environment. This allows the attacker to maintain control even if other access methods are discovered and remediated. The attacker can use the Automation Account to execute malicious code, steal sensitive data, or disrupt critical services, leading to significant financial and reputational damage. This can affect organizations of any size that rely on Azure for their infrastructure and operations.

## Recommendation

*   Deploy the Sigma rule "Azure Automation Account Created" to your SIEM and tune for your environment to detect account creations (rule.name).
*   Investigate the user or service principal responsible for creating new Automation Accounts (references).
*   Review the permissions granted to newly created Automation Accounts to identify any excessive privileges (references).
*   Monitor for suspicious activity originating from Automation Accounts, such as unauthorized access to resources or execution of unusual scripts (references).
*   Implement multi-factor authentication (MFA) for all Azure accounts, especially those with administrative privileges to prevent credential compromise (references).
*   Enforce the principle of least privilege to limit the impact of compromised accounts (references).
