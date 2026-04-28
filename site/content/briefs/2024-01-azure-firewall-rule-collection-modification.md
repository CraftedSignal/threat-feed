---
title: Azure Firewall Rule Collection Modification or Deletion
slug: 2024-01-azure-firewall-rule-collection-modification
description: An attacker may modify or delete Azure Firewall rule collections (Application, NAT, and Network) to impair defenses and potentially enable malicious traffic.
date: "2024-01-31T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - firewall
  - defense-impairment
vendors:
  - Microsoft
products:
  - Azure Firewall
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_firewall_rule_collection_modified_or_deleted.yml
rules:
  - title: Azure Firewall Rule Collection Modified or Deleted
    description: Identifies when Rule Collections (Application, NAT, and Network) are modified or deleted.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - impact
    data_sources:
      - azure
      - activitylogs
  - title: Azure Firewall Rule Collection Modified by Unusual User
    description: Detects Azure Firewall rule collection modifications performed by users who do not typically manage firewall resources.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - impact
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

The modification or deletion of Azure Firewall rule collections (Application, NAT, and Network) can indicate malicious activity within an Azure environment. Threat actors may target these rules to bypass security controls, allowing unauthorized network traffic, enabling data exfiltration, or facilitating lateral movement. Monitoring these changes is crucial for maintaining the integrity of network security policies and detecting potential breaches. This activity directly impacts an organization's ability to enforce its security posture, potentially exposing sensitive resources to unauthorized access.

## Attack Chain

1.  The attacker gains initial access to the Azure environment, potentially through compromised credentials or a vulnerability in an application.
2.  The attacker enumerates existing Azure Firewall resources to identify rule collections (Application, NAT, and Network) that can be modified or deleted.
3.  The attacker uses valid Azure credentials or exploits a misconfiguration to authenticate to the Azure Resource Manager API.
4.  The attacker crafts a malicious request to modify the target rule collection, potentially altering allowed ports, IP addresses, or protocols.
5.  Alternatively, the attacker crafts a request to delete an entire rule collection, effectively disabling its associated security controls.
6.  The attacker sends the request to the Azure Resource Manager API, executing the change to the firewall configuration.
7.  The modified or deleted rule collection now allows unauthorized traffic to bypass the firewall, potentially enabling lateral movement or data exfiltration.
8.  The attacker exploits the newly opened network paths to achieve their final objective, such as deploying ransomware or accessing sensitive data.

## Impact

Successful modification or deletion of Azure Firewall rule collections can have significant consequences. Unauthorized traffic could bypass security controls, enabling data exfiltration, lateral movement, or the deployment of malware. This could lead to data breaches, service disruptions, and financial losses. The impact depends on the scope of the modified or deleted rule collection and the resources it protects.

## Recommendation

*   Deploy the Sigma rule "Azure Firewall Rule Collection Modified or Deleted" to your SIEM and tune for your environment to detect unauthorized changes to firewall configurations.
*   Review Azure Activity Logs for any events matching the `operationName` values specified in the Sigma rule to identify suspicious activity.
*   Implement multi-factor authentication (MFA) for all Azure accounts, especially those with permissions to manage firewall resources, to reduce the risk of credential compromise.
*   Regularly audit Azure role-based access control (RBAC) assignments to ensure the principle of least privilege is followed and that only authorized users have permissions to modify firewall configurations.
