---
title: Azure Runbook Webhook Creation Detected
slug: 2024-01-03-azure-runbook-webhook-created
description: Detection of a new Azure Automation Runbook Webhook creation, potentially leading to unauthorized access and control over Azure resources by enabling unauthenticated URL triggers.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - runbook
  - webhook
  - persistence
vendors:
  - Microsoft
products:
  - Azure Automation
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.microsoft.com/en-us/azure/automation/overview
  - https://docs.microsoft.com/en-us/azure/automation/automation-runbook-types
  - https://docs.microsoft.com/en-us/azure/automation/automation-webhooks?tabs=portal
  - https://www.inversecos.com/2021/12/how-to-detect-malicious-azure.html
  - https://www.netspi.com/blog/technical/cloud-penetration-testing/maintaining-azure-persistence-via-automation-accounts/
  - https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/AZT503/AZT503-3/
  - https://attack.mitre.org/techniques/T1078/004/
rules:
  - title: Azure Runbook Webhook Created
    description: Detects the creation of an Azure Automation Runbook Webhook, which can be used for persistence and unauthorized execution.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure Runbook Creation
    description: Detects the creation of an Azure Automation Runbook, which is a prerequisite for webhook abuse.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - azure
      - activitylog
rules_count: 2
---

This alert focuses on the creation of new Azure Automation Runbook Webhooks within an Azure tenant. Attackers can exploit these webhooks, which trigger Automation Runbooks through unauthenticated URLs, to execute malicious code, create unauthorized user accounts, or establish persistence within the Azure environment. This activity is detected using Azure Audit events, specifically monitoring for the "Microsoft.Automation/automationAccounts/webhooks/write" operation. This is especially critical as successful exploitation can lead to full control over the Azure resources. Defenders should prioritize monitoring for unexpected or unauthorized webhook creation activities. This detection originated from Splunk's ES-CU detections as of April 2026.

## Attack Chain

1.  The attacker gains initial access to an Azure account, possibly through compromised credentials or exploiting a vulnerability.
2.  The attacker navigates to the Azure Automation service within the Azure portal.
3.  The attacker attempts to create a new Automation Account if one doesn't exist, or uses an existing one.
4.  The attacker creates a new Runbook designed to execute malicious tasks. This could include adding a new user account with elevated privileges.
5.  The attacker creates a webhook associated with the malicious Runbook. This generates an unauthenticated URL.
6.  The attacker configures the webhook to trigger the Runbook upon accessing the unauthenticated URL.
7.  The attacker tests the webhook URL to ensure the Runbook executes as intended.
8.  The attacker leverages the webhook URL to execute malicious actions within the Azure environment, such as creating new high privileged accounts or modifying existing infrastructure.

## Impact

Successful exploitation allows attackers to gain unauthorized access and control over Azure resources. This can result in data breaches, service disruptions, and further compromise of the environment. If not detected promptly, this can lead to significant financial and reputational damage. This issue impacts any organization using Azure Automation and exposes all data and resources managed within the impacted Azure tenant.

## Recommendation

*   Deploy the Sigma rule `Azure Runbook Webhook Created` to your SIEM and tune for your environment to detect the creation of malicious webhooks.
*   Investigate any detected instances of Azure Runbook Webhook creation, focusing on the user (`user`) and source IP (`src_ip`) involved.
*   Review Azure Activity logs for the "Microsoft.Automation/automationAccounts/webhooks/write" operation.
*   Monitor network traffic for suspicious connections to newly created webhook URLs (related to the created `object`).
*   Implement strict access control policies and multi-factor authentication for all Azure accounts to prevent initial compromise.
