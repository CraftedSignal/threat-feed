---
title: Azure Automation Webhook Created for Persistence
slug: 2024-01-azure-automation-webhook-created
description: Adversaries may create Azure Automation webhooks to trigger malicious runbooks for persistence in cloud environments.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
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
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1608
    technique_name: Stage Capabilities
references:
  - https://powerzure.readthedocs.io/en/latest/Functions/operational.html#create-backdoor
  - https://github.com/hausec/PowerZure
  - https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a
  - https://www.ciraltos.com/webhooks-and-azure-automation-runbooks/
rules:
  - title: Azure Automation Webhook Created
    description: Detects the creation of Azure Automation webhooks, which can be used for persistence.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - resource_development
    techniques:
      - T1546
      - T1608
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure Automation Webhook Action Detected
    description: Detects an action on Azure Automation webhooks, such as creation or modification.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - resource_development
    techniques:
      - T1546
      - T1608
    data_sources:
      - cloudtrail
      - azure
      - activitylog
rules_count: 2
---

This alert identifies the creation of Azure Automation webhooks, which adversaries may abuse to establish persistence within cloud environments. Azure Automation allows users to define and execute runbooks, which are scripts that automate tasks. Webhooks provide a mechanism to trigger these runbooks via HTTP requests. An attacker can create a webhook associated with a malicious runbook, allowing them to execute arbitrary code within the Azure environment whenever the webhook URL is accessed. This poses a significant risk, as it allows attackers to maintain a persistent foothold and potentially escalate their privileges. The detection rule focuses on identifying specific operation names within Azure activity logs related to webhook creation.

## Attack Chain

1. An attacker gains initial access to an Azure account, possibly through compromised credentials or exploiting a vulnerability.
2. The attacker navigates to the Azure Automation service within the compromised account.
3. The attacker creates a new runbook or modifies an existing one to include malicious code (e.g., PowerShell script to create a new user, exfiltrate data, or deploy malware).
4. The attacker creates a new webhook associated with the malicious runbook. The webhook is configured to be triggered by an HTTP request to a unique URL.
5. The attacker obtains the webhook URL.
6. The attacker triggers the webhook by sending an HTTP request to the URL, either manually or through an automated process.
7. The Azure Automation service executes the runbook associated with the webhook.
8. The malicious code within the runbook executes, achieving the attacker's objective (e.g., persistence, privilege escalation, data exfiltration).

## Impact

Successful exploitation allows attackers to establish a persistent presence within the Azure environment. This can lead to unauthorized access to sensitive data, deployment of malware, or further compromise of other resources within the cloud infrastructure. While the risk score is low, the long-term impact of persistence can be severe, potentially affecting hundreds or thousands of resources depending on the scope of the compromised Azure account.

## Recommendation

*   Deploy the Sigma rule "Azure Automation Webhook Created" to your SIEM and tune for your environment (rule below).
*   Review Azure activity logs for unusual webhook creation events, focusing on the `azure.activitylogs.operation_name` field as indicated in the rule (rule below).
*   Implement enhanced monitoring and alerting for webhook creation and execution activities to detect similar threats in the future as described in the Overview section.
*   Enforce multi-factor authentication (MFA) for all accounts with access to Azure Automation as mentioned in the Response and Remediation section.
