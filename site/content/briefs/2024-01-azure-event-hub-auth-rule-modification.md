---
title: Azure Event Hub Authorization Rule Created or Updated
slug: 2024-01-azure-event-hub-auth-rule-modification
description: Creation or modification of Azure Event Hub authorization rules can indicate unauthorized access or privilege escalation by adversaries using cryptographic keys to manage access to event hubs.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - azure
  - persistence
  - account-manipulation
vendors:
  - Microsoft
products:
  - Azure Event Hub
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://docs.microsoft.com/en-us/azure/event-hubs/authorize-access-shared-access-signature
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/003/
  - https://attack.mitre.org/techniques/T1552/
  - https://attack.mitre.org/techniques/T1552/005/
rules:
  - title: Azure Event Hub Authorization Rule Created or Updated
    description: Detects when an Event Hub Authorization Rule is created or updated in Azure, which could indicate unauthorized access or persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
      - T1098.003
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure Event Hub Auth Rule Key Retrieval
    description: Detects attempts to retrieve Event Hub authorization rule keys, potentially indicating credential access.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
      - T1552.005
    data_sources:
      - cloudtrail
      - azure
      - activitylog
rules_count: 2
---

The creation or modification of Azure Event Hub authorization rules can be an indicator of malicious activity. Event Hub authorization rules manage access via cryptographic keys, similar to administrative credentials. Attackers may target these rules to gain unauthorized access or escalate privileges, potentially leading to data exfiltration or other malicious actions within the Azure environment. The default `RootManageSharedAccessKey` rule, created with each Event Hub namespace, provides administrative access and is a particularly attractive target. This activity is detected via Azure Activity Logs, providing insight into potential misuse of these powerful access controls. The rule monitors for successful creation or modification events.

## Attack Chain

1. An attacker gains initial access to an Azure account, possibly through compromised credentials or an exposed service principal.
2. The attacker enumerates existing Event Hub namespaces within the Azure subscription to identify potential targets.
3. The attacker attempts to create a new authorization rule with elevated privileges (e.g., `manage` permissions) on a target Event Hub namespace.
4. Alternatively, the attacker modifies an existing authorization rule, such as adding or changing the associated cryptographic keys.
5. The attacker uses the newly created or modified authorization rule to generate a Shared Access Signature (SAS) token.
6. The SAS token is then used to authenticate to the Event Hub and perform unauthorized actions, such as reading or writing event data.
7. The attacker exfiltrates sensitive data from the Event Hub using the compromised authorization rule.

## Impact

A successful attack leveraging unauthorized Event Hub authorization rule modification can lead to significant data breaches and operational disruption. The severity depends on the sensitivity of the data within the Event Hubs. A compromised `RootManageSharedAccessKey` could grant an attacker full control over the Event Hub namespace and its data. The impact can include exfiltration of sensitive data, denial of service, or further compromise of other Azure resources.

## Recommendation

*   Deploy the Sigma rule "Azure Event Hub Authorization Rule Created or Updated" to your SIEM and tune for your environment to detect suspicious authorization rule modifications.
*   Review Azure Activity Logs (referenced in the rule) for unauthorized or unexpected creation or modification of Event Hub authorization rules, paying close attention to the user or service principal associated with the operation.
*   Implement conditional access policies to restrict access to Event Hub Authorization Rules based on user roles and network locations, as suggested in the overview.
*   Regularly rotate the cryptographic keys associated with Event Hub Authorization Rules, especially the `RootManageSharedAccessKey`, as outlined in the response recommendations.
*   Monitor for access patterns or data transfers from the affected Event Hubs following a rule change to detect potential data exfiltration, referencing the overview.
