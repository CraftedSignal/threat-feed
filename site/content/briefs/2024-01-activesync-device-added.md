---
title: New ActiveSync Allowed Device Added via PowerShell
slug: 2024-01-activesync-device-added
description: The rule detects the use of the Exchange PowerShell cmdlet, Set-CASMailbox, to add a new ActiveSync allowed device, potentially allowing attackers to gain persistent access to sensitive email data by adding unauthorized devices.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - exchange
  - activesync
  - powershell
  - persistence
vendors:
  - Microsoft
  - Crowdstrike
  - SentinelOne
  - Elastic
products:
  - Microsoft Defender XDR
  - Exchange Server
  - Elastic Defend
  - CrowdStrike
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/
  - https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps
rules:
  - title: ActiveSyncAllowedDeviceID Added via PowerShell
    description: Detects the use of PowerShell to add a new ActiveSyncAllowedDeviceID to a mailbox.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.001
      - T1098.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Calling Set-CASMailbox
    description: Detects processes other than Exchange Management Shell calling Set-CASMailbox, which can indicate malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.001
      - T1098.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies the use of the Exchange PowerShell cmdlet, `Set-CASMailbox`, to add a new ActiveSync allowed device. Attackers may target user email to collect sensitive information by adding unauthorized devices to a user's allowed ActiveSync devices. The rule focuses on detecting suspicious PowerShell activity by monitoring for specific command patterns indicative of unauthorized device additions. This activity can lead to persistent access to sensitive email data, bypassing normal authentication controls. The original Elastic detection rule was created on 2020/12/15 and updated on 2026/05/04. This matters for defenders because it highlights a persistence mechanism that can be difficult to detect through traditional means.

## Attack Chain

1. An attacker gains initial access to a privileged account with Exchange management permissions.
2. The attacker uses PowerShell to execute the `Set-CASMailbox` cmdlet.
3. The attacker modifies the `ActiveSyncAllowedDeviceIDs` attribute for a target user's mailbox.
4. The attacker adds a rogue device ID to the list of allowed devices.
5. The attacker configures a mobile device with the rogue device ID to synchronize with the target mailbox.
6. The attacker gains persistent access to the target user's email, calendar, and contacts.
7. The attacker exfiltrates sensitive data from the mailbox.
8. The attacker maintains persistence even after password changes by continuing to synchronize via the added device.

## Impact

Successful exploitation could lead to unauthorized access to sensitive email data, including confidential communications, financial information, and personal data. This can result in data breaches, compliance violations, and reputational damage. The scope of the impact depends on the privileges of the compromised account and the sensitivity of the data contained in the targeted mailboxes.

## Recommendation

*   Deploy the Sigma rule `ActiveSyncAllowedDeviceID Added via PowerShell` to your SIEM and tune for your environment to detect suspicious activity.
*   Enable Sysmon process-creation logging to capture PowerShell commands for the rule above.
*   Review Exchange audit logs for instances of `Set-CASMailbox` being used to modify `ActiveSyncAllowedDeviceIDs`.
*   Implement multi-factor authentication (MFA) for all accounts, especially those with Exchange management privileges.
*   Regularly audit ActiveSync device configurations to identify unauthorized devices.
