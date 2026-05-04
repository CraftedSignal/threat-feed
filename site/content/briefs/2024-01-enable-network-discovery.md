---
title: Windows Host Network Discovery Enabled via Netsh
slug: 2024-01-enable-network-discovery
description: Attackers can enable host network discovery via netsh.exe to weaken host firewall settings, facilitating lateral movement by identifying other systems on the network.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - firewall
vendors:
  - Microsoft
  - CrowdStrike
  - SentinelOne
  - Elastic
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - CrowdStrike
  - SentinelOne Cloud Funnel
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_enable_network_discovery_with_netsh.toml
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/004/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Enable Host Network Discovery via Netsh
    description: Identifies use of the netsh.exe program to enable host discovery via the network.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - process_creation
      - windows
  - title: Netsh Firewall Rule Modification
    description: Detects netsh.exe being used to modify firewall rules, which can indicate defense evasion.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can leverage the `netsh.exe` utility to modify Windows Firewall settings, specifically enabling Network Discovery. This setting allows a host to broadcast its presence and services, making it easier for attackers to identify potential targets within the network for lateral movement. The behavior is often a post-exploitation technique to weaken host-based defenses after gaining initial access. The modification uses netsh.exe, a command-line scripting utility for managing network configurations. This activity can be easily scripted and automated, making it a common step in reconnaissance and lateral movement playbooks. Defenders should monitor for unauthorized use of `netsh.exe` to modify firewall settings.

## Attack Chain

1.  Attacker gains initial access to a Windows host.
2.  Attacker executes `netsh.exe` with elevated privileges.
3.  `netsh.exe` is used to modify the Windows Firewall configuration.
4.  The specific command executed enables Network Discovery using the `netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes` syntax.
5.  The firewall rule group "Network Discovery" is modified to allow inbound and outbound traffic.
6.  The compromised host begins sending out broadcast messages, advertising its presence and services on the network.
7.  The attacker uses the information gathered to identify other vulnerable systems on the network.
8.  The attacker moves laterally to other systems based on the discovery information.

## Impact

Successful exploitation allows attackers to easily enumerate and identify other vulnerable systems within the network. This can lead to rapid lateral movement, further compromising the environment. The risk is heightened when the compromised host has access to sensitive data or critical systems. There is no specific victim count or sector targeted mentioned in the provided source.

## Recommendation

*   Deploy the Sigma rule "Enable Host Network Discovery via Netsh" to your SIEM to detect the use of `netsh.exe` to enable network discovery (see rule below).
*   Enable Windows Firewall logging and monitor for changes to firewall rules, specifically those related to Network Discovery.
*   Review and restrict the use of `netsh.exe` to authorized personnel and systems only.
