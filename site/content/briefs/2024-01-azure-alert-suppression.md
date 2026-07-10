---
title: Azure Alert Suppression Rule Created or Modified
slug: 2024-01-azure-alert-suppression
description: Detection of Azure alert suppression rule creation or modification events, which can be used by attackers to disable security alerts and evade detection.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - azure
  - defense-evasion
  - cloud
vendors:
  - Microsoft
products:
  - Azure
  - Azure Security Center
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
  - https://docs.microsoft.com/en-us/rest/api/securitycenter/alerts-suppression-rules/update
rules:
  - title: Azure Alert Suppression Rule Created or Modified
    description: Detects the creation or modification of alert suppression rules in Azure, which can be used by attackers to disable security alerts and evade detection.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Azure Alert Suppression Rule Deletion
    description: Detects the deletion of alert suppression rules in Azure
    platform: sigma
    severity: informational
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

This detection rule identifies the creation or modification of alert suppression rules within Azure environments. Alert suppression rules are designed to filter out known false positives or low-priority alerts, reducing noise and improving the efficiency of security operations. However, malicious actors can abuse these rules to hide their activity by suppressing alerts related to their attacks. This rule focuses on successful "MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE" operations, indicating a change to the alert suppression configuration. Detecting these changes allows security teams to monitor for unauthorized or suspicious modifications that could lead to a significant reduction in security visibility. This rule is applicable to organizations using Azure and relies on the availability of Azure Activity Logs.

## Attack Chain

1. An attacker gains initial access to an Azure account through compromised credentials or by exploiting a vulnerability.
2. The attacker identifies existing alert rules and their configurations within the Azure Security Center.
3. Using their access, the attacker creates a new alert suppression rule or modifies an existing one.
4. The suppression rule is configured to target specific alerts related to the attacker's activities. The `MICROSOFT.SECURITY/ALERTSSUPPRESSIONRULES/WRITE` operation is executed.
5. The Azure Activity Logs record a successful write event for the alert suppression rule.
6. With the suppression rule active, alerts related to the attacker's actions are no longer triggered, effectively evading detection.
7. The attacker continues their malicious activities, such as data exfiltration or resource exploitation, without triggering security alerts.
8. The attacker maintains persistence, knowing their activities are now less likely to be detected due to the alert suppression.

## Impact

Successful exploitation of alert suppression rules can lead to a significant decrease in security visibility within Azure environments. Attackers can operate undetected, potentially leading to data breaches, unauthorized resource access, and other malicious activities. The impact is a function of how long the attacker can remain undetected while they are actively suppressing alerts related to their activities. If critical alerts are suppressed, it can result in substantial financial losses, reputational damage, and regulatory compliance violations.

## Recommendation

*   Deploy the Sigma rule "Azure Alert Suppression Rule Created or Modified" to your SIEM and tune for your environment to detect unauthorized changes to alert suppression rules.
*   Enable Azure Activity Logs to ensure the necessary data is available for the Sigma rule to function (reference: log source in the Sigma rule).
*   Review and update access controls and permissions for creating or modifying suppression rules to ensure only authorized personnel can make such changes. (reference: Overview section).
*   Investigate any identified instances of alert suppression rule creation or modification to determine if they are legitimate and authorized (reference: Sigma rule description).
*   Establish a baseline of expected changes and create exceptions for known maintenance periods or personnel (reference: False positive analysis section).
