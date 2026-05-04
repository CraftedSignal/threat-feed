---
title: DNS Global Query Block List Modified or Disabled
slug: 2024-07-dns-gqbl-modified
description: Attackers with DNSAdmin privileges can modify or disable the DNS Global Query Block List (GQBL) in Windows, allowing exploitation of hosts running WPAD with default settings for privilege escalation and lateral movement.
date: "2024-07-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - registry-modification
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Elastic Endgame
  - Crowdstrike
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
references:
  - https://cube0x0.github.io/Pocing-Beyond-DA/
  - https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/wpad-spoofing
  - https://www.netspi.com/blog/technical-blog/network-penetration-testing/adidns-revisited/
rules:
  - title: Registry Modification of DNS Global Query Block List
    description: Detects modifications to the DNS Global Query Block List, which can indicate an attempt to disable or bypass security controls.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562
    data_sources:
      - registry_set
      - windows
  - title: Sysmon - DNS Global Query Block List Modified or Disabled
    description: Identifies changes to the DNS Global Query Block List (GQBL) using Sysmon event data.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The DNS Global Query Block List (GQBL) is a Windows security feature designed to prevent the resolution of specific DNS names, commonly exploited in attacks like WPAD spoofing. Attackers who have obtained elevated privileges, such as DNSAdmin, can modify or disable this list to bypass security controls. This allows exploitation of hosts running WPAD with default settings. The modification of the GQBL can be used for privilege escalation and lateral movement within a network. This rule detects changes to the registry values associated with the GQBL, specifically "EnableGlobalQueryBlockList" and "GlobalQueryBlockList." This activity could indicate an attacker attempting to weaken defenses to facilitate further malicious activities.

## Attack Chain

1.  An attacker gains initial access to a system, possibly through compromised credentials or exploiting a vulnerability.
2.  The attacker escalates privileges to obtain DNSAdmin rights.
3.  The attacker modifies the "EnableGlobalQueryBlockList" registry value to "0" or "0x00000000," effectively disabling the GQBL.
4.  Alternatively, the attacker modifies the "GlobalQueryBlockList" registry value to remove "wpad" from the list.
5.  The attacker leverages the disabled GQBL to conduct WPAD spoofing attacks, redirecting network traffic to attacker-controlled servers.
6.  The attacker captures user credentials transmitted during WPAD authentication.
7.  The attacker uses the captured credentials to move laterally to other systems on the network.
8.  The attacker achieves their final objective, such as data exfiltration or deploying ransomware.

## Impact

Successful modification or disabling of the DNS Global Query Block List can lead to WPAD spoofing attacks, credential theft, lateral movement, and ultimately, complete compromise of the network. Attackers can leverage this technique to gain unauthorized access to sensitive data or systems. The impact includes potential data breaches, financial loss, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Registry Modification of DNS Global Query Block List` to your SIEM to detect unauthorized changes to the GQBL configuration.
*   Enable Sysmon registry event logging to capture the necessary events for the Sigma rule to function (reference the logsource in the rule).
*   Review and restrict DNSAdmin privileges to only necessary accounts to minimize the attack surface (reference: Overview section).
*   Monitor network traffic for unusual DNS queries or WPAD-related activity, correlating with registry modification events (reference: Attack Chain step 5).
*   Regularly audit registry settings related to DNS configuration, including the GQBL, to identify unauthorized modifications (reference: Attack Chain steps 3 & 4).
*   Update security policies and procedures to include specific measures for monitoring and protecting the DNS Global Query Block List (reference: Impact section).
