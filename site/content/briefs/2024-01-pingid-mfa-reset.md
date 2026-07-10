---
title: PingID New MFA Method After Credential Reset
slug: 2024-01-pingid-mfa-reset
description: Detection of a new MFA device pairing in PingID shortly after a password reset in Windows Event Logs, potentially indicating a social engineering attack and unauthorized account access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - pingid
  - mfa
  - credential-access
vendors:
  - Ping Identity
  - Microsoft
products:
  - PingID
  - Windows
  - Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1621
    technique_name: Multi-Factor Authentication Interception
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/defend-your-users-from-mfa-fatigue-attacks/ba-p/2365677
  - https://www.bleepingcomputer.com/news/security/mfa-fatigue-hackers-new-favorite-tactic-in-high-profile-breaches/
  - https://attack.mitre.org/techniques/T1098/005/
  - https://attack.mitre.org/techniques/T1556/006/
  - https://docs.pingidentity.com/r/en-us/pingoneforenterprise/p14e_subscriptions?tocId=3xhnxjX3VzKNs3SXigWnQA
rules:
  - title: PingID Device Paired Event
    description: Detects a PingID Device Paired event, which is a key indicator in MFA takeover scenarios.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1556.006
    data_sources:
      - webserver
      - linux
  - title: Windows Password Change Event
    description: Detects Windows Event ID 4723 or 4724 indicating a password change.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1556.006
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This analytic identifies suspicious activity where a new MFA device is paired with a user account in PingID shortly after a password reset. The detection logic correlates Windows Event Logs for password changes (Event ID 4723, 4724) with PingID logs indicating device pairing events. This behavior is significant because it can indicate a social engineering attack, where a threat actor impersonates a valid user to reset their credentials and add a new MFA device under their control. The observed activity focuses on gaining unauthorized access to user accounts by bypassing traditional security measures through MFA manipulation. The timeframe analyzed is within one hour of the password reset.

## Attack Chain

1.  The attacker conducts reconnaissance to identify a target user within the organization.
2.  The attacker initiates a password reset for the target user, possibly through social engineering or exploiting a vulnerability in the password reset process.
3.  Windows Event Logs record a password change event (Event ID 4723 or 4724) on the Active Directory Domain Controller.
4.  The attacker pairs a new MFA device with the target user's PingID account. This could involve intercepting the original MFA device or using other unknown MFA enrollment bypass techniques.
5.  PingID logs record a "Device Paired" event, including information about the device (e.g., IP address, device model).
6.  The attacker leverages the newly paired MFA device to authenticate as the target user, bypassing legitimate MFA controls.
7.  The attacker gains unauthorized access to sensitive applications, data, and resources accessible to the target user.

## Impact

A successful attack allows the adversary to gain persistent access to a compromised account, bypassing multi-factor authentication. This could lead to unauthorized access to sensitive data, financial fraud, or further lateral movement within the organization. The impact includes potential data breaches, reputational damage, and financial loss. The references suggest that MFA fatigue is becoming a more common attack vector.

## Recommendation

*   Deploy the Sigma rule `PingID New MFA Method After Credential Reset` to your SIEM and tune the `timeDiffRaw` parameter for your environment to reduce false positives.
*   Enable Windows Event Log collection on Active Directory Domain Controllers to capture password change events (Event ID 4723, 4724) as required by the provided Sigma rule.
*   Ingest PingID logs, either via Webhook or Push Subscription, into your SIEM to enable correlation with password reset events for identifying potential MFA takeover attempts as used by the Sigma rule.
*   Implement stricter password reset policies and MFA enrollment procedures to reduce the risk of social engineering attacks.
