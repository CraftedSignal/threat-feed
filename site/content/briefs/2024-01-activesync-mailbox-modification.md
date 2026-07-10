---
title: Exchange PowerShell Used to Add New ActiveSync Allowed Device
slug: 2024-01-activesync-mailbox-modification
description: An adversary may use the Exchange PowerShell cmdlet, Set-CASMailbox, to add a new ActiveSync allowed device, potentially gaining persistent access to a user's email and sensitive information.
date: "2024-01-02T15:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - exchange
  - powershell
  - activesync
  - persistence
vendors:
  - Microsoft
products:
  - Microsoft Exchange Server
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
  - title: Detect Suspicious ActiveSync Mailbox Modification via PowerShell
    description: Detects the use of PowerShell to modify ActiveSync settings for a mailbox, specifically adding a new allowed device.
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
  - title: Detect Suspicious ActiveSync Mailbox Modification - Alternate PowerShell
    description: Detects the use of pwsh.exe to modify ActiveSync settings for a mailbox, specifically adding a new allowed device.
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
rules_count: 2
---

Attackers are increasingly targeting Exchange servers to gain access to sensitive email data. This activity involves the use of PowerShell to modify mailbox settings, specifically to add new ActiveSync allowed devices. The addition of rogue devices allows the attacker to maintain persistent access, bypassing typical authentication controls. This technique has been observed in intrusions following initial compromise via vulnerabilities like the SolarWinds supply chain attack. This can lead to long-term access to sensitive information, facilitating data exfiltration or further exploitation within the compromised organization. Defenders must monitor PowerShell activity related to Exchange management and validate any changes to ActiveSync configurations.

## Attack Chain

1. Initial access is gained to a compromised host, potentially through exploitation of a vulnerability or stolen credentials.
2. The attacker uses PowerShell to interact with the Exchange Management Shell (EMS).
3. The `Set-CASMailbox` cmdlet is invoked with the `ActiveSyncAllowedDeviceIDs` parameter.
4. A new, unauthorized device ID is added to the list of allowed devices for a target mailbox.
5. The attacker uses the newly authorized device to synchronize with the target mailbox via the ActiveSync protocol.
6. Email data, including sensitive information, is accessed and potentially exfiltrated from the mailbox.
7. The attacker maintains persistent access to the mailbox through the authorized device, even if the user changes their password.

## Impact

Successful execution of this attack allows adversaries to maintain persistent access to targeted mailboxes, enabling the collection of sensitive information. This can lead to financial losses, reputational damage, and exposure of confidential data. The number of victims can vary depending on the scope of the attacker's objectives. The technique has been observed in attacks targeting organizations across various sectors. If successful, attackers can exfiltrate sensitive data, compromise internal communications, and potentially gain further access to the organization's network.

## Recommendation

*   Monitor process execution for PowerShell commands containing `Set-CASMailbox` and `ActiveSyncAllowedDeviceIDs` to detect suspicious activity (see Sigma rule "Detect Suspicious ActiveSync Mailbox Modification via PowerShell").
*   Enable Sysmon process creation logging with command line arguments to capture PowerShell activity (reference Sigma rule logsource).
*   Review Exchange audit logs for modifications to `ActiveSyncAllowedDeviceIDs` attribute to identify unauthorized device additions.
*   Implement multi-factor authentication (MFA) to mitigate the risk of credential compromise (reference: MITRE ATT&CK T1114).
*   Regularly audit ActiveSync device configurations for unauthorized devices (reference: description).
