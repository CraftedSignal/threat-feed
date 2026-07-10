---
title: Entra ID User Sign-in with Unusual Non-Managed Device
slug: 2024-01-entra-id-unusual-device-login
description: Detects Microsoft Entra ID user sign-ins from devices not typically used or managed, indicating potential account compromise or unauthorized access via device registration for persistence.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - azure
  - entra-id
  - persistence
  - device-registration
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://pushsecurity.com/blog/consentfix
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
rules:
  - title: Entra ID Unusual Device Sign-in
    description: Detects Entra ID user sign-ins from devices not typically used by the user, indicating potential account compromise or unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1078.004
      - T1098.005
    data_sources:
      - authentication
      - azure
  - title: Entra ID Sign-in with Unbound Session Status
    description: Detects Entra ID sign-ins with an unbound session status, which can indicate token theft or manipulation.
    platform: sigma
    severity: low
    tactics:
      - initial_access
      - persistence
    data_sources:
      - authentication
      - azure
rules_count: 2
---

This detection identifies instances where a Microsoft Entra ID user logs in from a device that is both unusual for that user and not managed by the organization. The rule leverages Microsoft Entra ID Sign-In logs to compare the device used in the sign-in attempt against the user's typical device usage patterns. A successful attack may involve an adversary registering a new device to obtain a Primary Refresh Token (PRT), which enables them to maintain persistent access to the environment. This activity can begin from initial access through compromised credentials or other methods. This rule is designed to detect unusual access patterns that might signify malicious activity, specifically within Microsoft Entra ID environments. The rule leverages Azure sign-in logs to identify potentially compromised or malicious accounts and devices.

## Attack Chain

1.  The attacker gains initial access through compromised credentials or other methods (e.g., phishing, credential stuffing).
2.  The attacker registers a new, non-managed device within the Entra ID environment.
3.  The compromised user account is used to sign in from the newly registered, unusual device.
4.  The sign-in attempt generates a Microsoft Entra ID Sign-In log event.
5.  The log event is evaluated against the user's historical device usage patterns.
6.  Because the device is new and unusual for the user, the detection rule triggers.
7.  The attacker obtains a Primary Refresh Token (PRT) from the registered device.
8.  The attacker uses the PRT for persistent access to Entra ID resources, potentially leading to data exfiltration or further malicious activities.

## Impact

Compromised Entra ID accounts can lead to unauthorized access to sensitive cloud resources and data. Successful exploitation enables attackers to maintain persistence and potentially escalate their privileges within the cloud environment. Lateral movement and data exfiltration may occur if the attacker gains access to high-value accounts or resources. While this specific detection has a low severity, it serves as an early warning sign of more significant compromise. The number of affected users will vary depending on the scope of the initial compromise and the attacker's subsequent actions.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune it to reduce false positives based on your environment's baseline (e.g., frequent device changes) and user behavior.
*   Review the Microsoft Entra ID Sign-In logs for the affected user(s) to identify any other unusual activity (`azure.signinlogs.properties.user_principal_name` and `azure.signinlogs.properties.device_detail.device_id`).
*   Investigate the device identified in the alert to determine if it is managed and authorized (`azure.signinlogs.properties.device_detail.is_managed`).
*   Review the conditional access policies in place to ensure they are sufficient to prevent unauthorized access, especially from non-managed devices.
*   Monitor the Azure Event Hub for any anomalies related to device registration or authentication events.
*   Consider adding exceptions for verified devices that are known to be used by the user to reduce false positives.
