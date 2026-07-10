---
title: Entra ID Protection Alert Followed by Device Registration
slug: 2024-01-entra-id-protection-device-registration
description: Detection of a Microsoft Entra ID protection alert followed by a new device registration attempt by the same user, potentially indicating account compromise and unauthorized device registration for persistence.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - entra_id
  - persistence
  - device_registration
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft Entra ID Protection
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-sign-ins-log-schema
  - https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/overview-identity-protection
  - https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk
  - https://docs.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-investigate-risk#investigation-framework
rules:
  - title: Entra ID Protection User Alert and Device Registration
    description: Detects a sequence of events where a Microsoft Entra ID protection alert is followed by an attempt to register a new device by the same user principal.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098.005
    data_sources:
      - cloudtrail
      - azure
  - title: Entra ID Device Registration Activity
    description: Detects device registration events in Azure Audit Logs.
    platform: sigma
    severity: informational
    tactics:
      - persistence
    techniques:
      - T1098.005
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

This alert identifies a suspicious sequence of events within Microsoft Entra ID: a prior Entra ID Protection alert concerning a user, immediately followed by that same user attempting to register a new device. This activity pattern suggests a compromised account might be used to register a rogue device. This can lead to persistence, as a registered device can grant ongoing access to cloud resources, even if the initial account compromise is remediated. The rule specifically looks at logs from Azure Identity Protection and Audit Logs to correlate these events within a 5-minute timeframe. Defenders should investigate such alerts promptly to determine if an account has been compromised and whether unauthorized access to resources has occurred.

## Attack Chain

1.  The attacker gains unauthorized access to a valid user account, potentially through phishing or credential stuffing.
2.  Microsoft Entra ID Protection detects anomalous activity related to the compromised account (e.g., unusual sign-in location, impossible travel).
3.  An Entra ID Protection alert is triggered due to the suspicious account activity.
4.  The attacker attempts to register a new device using the compromised account. This registration might involve bypassing device enrollment policies.
5.  The device registration is logged in Azure Audit Logs.
6.  The attacker uses the registered device to access cloud resources and services.
7.  The attacker maintains persistent access to the environment through the registered device.
8.  The attacker performs malicious activities such as data exfiltration, privilege escalation, or lateral movement using the compromised account and registered device.

## Impact

A successful attack can lead to unauthorized access to sensitive data and cloud resources. A compromised account with a rogue registered device allows an attacker to maintain persistent access to the environment. This may bypass standard security controls and allow for data exfiltration, lateral movement, and further compromise of the environment. The number of victims and affected sectors is currently unknown but could be extensive depending on the compromised account's privileges and the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule `Entra ID Protection User Alert and Device Registration` to your SIEM and tune for your environment. This rule detects the specific sequence of Entra ID Protection alerts followed by device registration attempts.
*   Investigate any alerts triggered by the `Entra ID Protection User Alert and Device Registration` rule, focusing on the user account involved and the characteristics of the device being registered.
*   Review Microsoft's security best practices for identity management and consider enabling multi-factor authentication for all users, as recommended in the references.
*   Monitor Azure Audit Logs for device registration events and correlate them with other security alerts and events in your environment, as the rule specifies.
