---
title: M365 or Entra ID Identity Sign-in from a Suspicious Source
slug: 2026-05-m365-entra-suspicious-source
description: This rule correlates Entra-ID or Microsoft 365 mail successful sign-in events with network security alerts by source address, indicating potential initial access via compromised credentials.
date: "2026-05-22T18:36:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - initial-access
  - cloud
  - entra-id
  - m365
vendors:
  - Microsoft
products:
  - Entra ID
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/initial_access_azure_o365_with_network_alert.toml
  - https://attack.mitre.org/techniques/T1078/
  - https://attack.mitre.org/tactics/TA0001/
  - https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices
rules:
  - title: Detect M365 Mail Access After Network Alert
    description: Detects successful M365 mail access (MailItemsAccessed) following a network security alert from the same source IP, indicating potential account compromise.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - network_connection
      - azure
  - title: Detect Entra ID Sign-in After Network Alert
    description: Detects successful Entra ID sign-in events following a network security alert from the same source IP, suggesting possible credential compromise.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection rule correlates successful sign-in events in Entra ID (formerly Azure AD) or Microsoft 365 with network security alerts originating from the same source IP address. The rule aims to identify instances where an adversary might trigger network security alerts, such as those related to IP reputation or anomalous network activity, before successfully gaining access to cloud resources. This approach helps detect potentially compromised accounts used to access cloud services from suspicious or malicious sources. The rule leverages data from O365 audit logs, Azure sign-in logs, and generic network security alerts, providing a higher-order correlation for enhanced threat detection.

## Attack Chain

1. An attacker compromises user credentials through phishing or other means.
2. The attacker attempts to access cloud resources (Entra ID or Microsoft 365) from a suspicious IP address.
3. The suspicious IP triggers a network security alert based on reputation or anomalous activity.
4. The attacker successfully authenticates to Entra ID or Microsoft 365 using the compromised credentials.
5. The successful sign-in event is logged in Azure sign-in logs or O365 audit logs.
6. The rule correlates the network security alert and the successful sign-in event based on the source IP address.
7. The attacker gains initial access to the cloud environment.
8. The attacker performs malicious actions within the cloud environment, such as accessing mail items (MailItemsAccessed).

## Impact

A successful attack can lead to unauthorized access to sensitive data, lateral movement within the cloud environment, and potential data exfiltration.  Compromised accounts could be used to send phishing emails, modify configurations, or deploy malicious applications, leading to significant business disruption and financial loss. The severity is high due to the potential for broad access and control within the targeted cloud environment.

## Recommendation

*   Deploy the "M365 or Entra ID Identity Sign-in from a Suspicious Source" rule to your SIEM and tune for your environment.
*   Investigate all alerts associated with the source IP address identified by the rule to determine the root cause of the network security alert.
*   Enable multi-factor authentication (MFA) for all users to mitigate the risk of credential compromise, as suggested in the Microsoft security best practices [outlined](https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices).
*   Review and update logging and audit policies based on incident response data to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).
*   Use the provided investigation guide within the rule description to triage and analyze detected incidents efficiently.
*   Enable Azure Fleet integration and Office 365 Logs Fleet integration for proper log collection as per the rule's [Setup] instructions.
