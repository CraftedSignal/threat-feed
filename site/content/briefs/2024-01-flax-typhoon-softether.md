---
title: Flax Typhoon Masquerading SoftEther VPN as Legitimate Windows Binaries
slug: 2024-01-flax-typhoon-softether
description: The Flax Typhoon group uses SoftEther VPN, masquerading the VPN client as legitimate Windows binaries like conhost.exe and dllhost.exe, to obfuscate their network activity within compromised Taiwanese organizations.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Flax Typhoon
  - Ethereal Panda
tags:
  - flax-typhoon
  - defense-evasion
  - lateral-movement
  - vpn
  - process-masquerading
vendors:
  - SoftEther
  - Microsoft
  - Splunk
products:
  - SoftEther VPN
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1572
    technique_name: Application Layer Protocol
references:
  - https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/
rules:
  - title: SoftEther VPN Masquerading as conhost.exe or dllhost.exe
    description: Detects SoftEther VPN client running as conhost.exe or dllhost.exe, a technique used by Flax Typhoon.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1572
    data_sources:
      - process_creation
      - windows
  - title: SoftEther VPN with vpnbridge Filename Masquerading
    description: Detects SoftEther VPN client using vpnbridge filename to hide its activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036
      - T1572
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Flax Typhoon group has been observed using SoftEther VPN software to hide their network activity after gaining access to Taiwanese organizations. This activity, observed as of August 2023, involves renaming the SoftEther VPN client executable to masquerade as legitimate Windows processes, specifically `conhost.exe` and `dllhost.exe`. By doing so, they attempt to blend in with normal system activity and evade detection. The group's activity highlights a trend of leveraging legitimate tools for malicious purposes. This allows them to maintain a low profile and persist within compromised networks for extended periods. Defenders should be aware of this tactic and implement detections to identify SoftEther VPN processes running under unexpected names.

## Attack Chain

1.  Initial compromise of a Taiwanese organization through unknown means.
2.  Deployment of SoftEther VPN client onto the compromised system.
3.  Renaming of the SoftEther VPN client executable to `conhost.exe` or `dllhost.exe`.
4.  Execution of the renamed SoftEther VPN client to establish a VPN connection.
5.  Network traffic is routed through the SoftEther VPN, masking the origin of malicious activity.
6.  Lateral movement within the network using the VPN connection for obfuscation.
7.  Data exfiltration or other malicious activities, further concealed by the VPN.
8.  Maintaining persistence by ensuring the renamed VPN client automatically starts on system reboot, providing continuous obfuscation for their activities.

## Impact

The successful deployment of this technique allows the Flax Typhoon group to operate within compromised networks with reduced visibility. By masquerading the VPN client as legitimate processes, they make it more difficult for defenders to identify and respond to malicious activity. This can lead to prolonged periods of undetected data theft, system compromise, and other harmful outcomes. While the exact number of victims is unknown, the targeting of Taiwanese organizations suggests a focused campaign with potentially significant impact on national security and economic interests.

## Recommendation

*   Implement the provided Sigma rule to detect SoftEther VPN binaries running under the names `conhost.exe` or `dllhost.exe` in your SIEM (see rules).
*   Investigate any instances of `conhost.exe` or `dllhost.exe` processes with a company name containing "SoftEther" or an original filename matching "vpnbridge*.exe" (see rules).
*   Monitor process creation events (Event ID 1 in Sysmon) for unexpected executions of renamed binaries.
*   Review network connection logs for outbound traffic originating from `conhost.exe` or `dllhost.exe` to external VPN servers, potentially indicating masqueraded SoftEther VPN activity.
