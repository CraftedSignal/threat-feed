---
title: Windows EventLog ChannelAccess Registry Modification
slug: 2024-01-eventlog-channelaccess-registry-set
description: An attacker modifies the Windows EventLog ChannelAccess registry value to evade defenses by blocking security products from accessing event logs.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - eventlog
  - windows
vendors:
  - Microsoft
products:
  - Sysmon
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://web.archive.org/web/20220710181255/https://blog.minerva-labs.com/lockbit-3.0-aka-lockbit-black-is-here-with-a-new-icon-new-ransom-note-new-wallpaper-but-less-evasiveness
  - https://attack.mitre.org/techniques/T1562/002/
rules:
  - title: Registry Modification of EventLog ChannelAccess
    description: Detects modifications to the EventLog ChannelAccess registry value, which can be used to blind security products.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - registry_set
      - windows
  - title: Sysmon EventLog ChannelAccess Registry Value Set
    description: Detects when the EventLog ChannelAccess registry value is set.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This threat brief details the detection of suspicious modifications to the EventLog security descriptor registry value in Windows systems. Attackers can manipulate the "CustomSD" value within the "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\<Channel>\CustomSD" path to alter access permissions, effectively blinding security products that rely on event log data. This technique, often employed for defense evasion, can prevent security tools and administrators from monitoring or responding to malicious activity. LockBit ransomware has been observed using similar techniques. Detecting and preventing these modifications is crucial for maintaining visibility and incident response capabilities.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through compromised credentials or exploiting a vulnerability).
2.  The attacker elevates privileges to obtain the necessary permissions to modify the registry.
3.  The attacker navigates to the specific registry path: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\<Channel>\CustomSD.
4.  The attacker modifies the "ChannelAccess" registry value (CustomSD) to restrict access to the event logs. This involves manipulating the Security Descriptor Definition Language (SDDL) string.
5.  The modified SDDL string restricts access for specific users, groups, or processes, including security products that ingest event logs.
6.  Security products are now unable to collect or analyze event logs, hindering detection and incident response.
7.  The attacker performs malicious activities, such as lateral movement or data exfiltration, without being detected through standard event log monitoring.
8.  The final objective is to achieve persistence and complete the attack (e.g., ransomware deployment, data theft) without triggering alerts.

## Impact

Successful modification of the EventLog ChannelAccess registry value can severely impair an organization's ability to detect and respond to security incidents. This can lead to delayed detection of malware infections, data breaches, and other malicious activities. Specifically, LockBit ransomware has been observed using similar techniques to evade detection. The number of affected systems depends on the scope of the attacker's access and the effectiveness of their evasion techniques. This blind spot allows attackers to operate with impunity, increasing the potential for significant financial and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Registry Modification of EventLog ChannelAccess` to your SIEM to detect suspicious modifications to the "ChannelAccess" registry value (CustomSD) under the "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog" path.
*   Enable Sysmon Event ID 13 to ensure registry modifications are captured and available for analysis, enabling the Sigma rule to function correctly.
*   Investigate any alerts triggered by the `Registry Modification of EventLog ChannelAccess` rule, focusing on processes modifying the registry and the associated users.
*   Monitor for unexpected or unauthorized changes to SDDL strings within the EventLog registry keys, as these can indicate malicious attempts to evade detection.
*   Review and harden registry permissions to prevent unauthorized modifications, reducing the attack surface for this technique.
