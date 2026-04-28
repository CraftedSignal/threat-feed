---
title: Azure Service Principal Removal Detection
slug: 2024-01-azure-service-principal-removed
description: Detection of a service principal removal in Azure, potentially indicating malicious activity or an attempt to remove evidence of a compromise.
date: "2024-01-03T14:27:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - service principal
  - stealth
  - cloud
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#application-proxy
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_service_principal_removed.yml
rules:
  - title: Azure Service Principal Removed - Detailed
    description: Identifies when a service principal was removed in Azure, with additional context.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    data_sources:
      - azure
      - activitylogs
  - title: Azure Service Principal Removed - Failed Attempt
    description: Identifies when an attempt to remove a service principal in Azure fails.
    platform: sigma
    severity: low
    tactics:
      - stealth
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

The removal of a service principal within an Azure environment can be indicative of various activities, ranging from legitimate administrative tasks to malicious actions undertaken by threat actors attempting to cover their tracks. While service principals are routinely removed as part of lifecycle management, unauthorized or unexpected removals should be investigated promptly. This detection focuses on identifying such removals through Azure Activity Logs, allowing security teams to quickly respond to potentially suspicious events.

## Attack Chain

1.  The attacker gains unauthorized access to an Azure account through compromised credentials or other means.
2.  The attacker identifies a service principal used for malicious purposes or to maintain persistence.
3.  The attacker attempts to remove the service principal to evade detection or disrupt incident response efforts.
4.  The attacker executes the necessary commands or uses the Azure portal to initiate the service principal removal. This action is logged in the Azure Activity Logs.
5.  The Azure Activity Logs record an event with the message "Remove service principal".
6.  The detection rule triggers based on the "Remove service principal" message in the Azure Activity Logs.
7.  Security analysts investigate the event, examining the user identity, user agent, and hostname associated with the removal.
8.  If the removal is deemed unauthorized or suspicious, further incident response procedures are initiated.

## Impact

Successful removal of a service principal by a malicious actor can disrupt legitimate applications relying on that principal for authentication and authorization. It can also hinder incident response efforts by eliminating a potential avenue for investigation or remediation. The impact can range from service disruptions to prolonged breaches if the attacker successfully covers their tracks. The number of affected applications and the severity of the disruption depend on the role and permissions associated with the removed service principal.

## Recommendation

*   Deploy the Sigma rule "Azure Service Principal Removed" to your SIEM and tune for your environment, focusing on identifying legitimate administrator activity to reduce false positives.
*   Investigate any detected instance of service principal removal, focusing on the user identity, user agent, and hostname from the Azure Activity Logs to determine legitimacy.
*   Review Azure AD audit logs for related activities occurring before and after the service principal removal.
