---
title: Netsh Used to Enable Network Discovery
slug: 2024-01-netsh-network-discovery
description: Adversaries may use the `netsh.exe` command-line tool to enable Network Discovery via the Windows firewall, weakening host defenses and facilitating lateral movement by identifying other systems on the network.
date: "2024-01-03T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - firewall
  - lateral-movement
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/004/
rules:
  - title: Detect Netsh Enabling Network Discovery
    description: Detects the execution of netsh.exe to enable Network Discovery through the Windows Firewall.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Netsh Firewall Modification (Generic)
    description: Detects the execution of netsh.exe to modify Windows Firewall rules, which may indicate defense evasion.
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

Attackers can exploit the `netsh.exe` utility to modify Windows Firewall settings, specifically enabling Network Discovery. This weakens the host's defenses and can reveal the host to other systems on the network, making it easier for adversaries to perform reconnaissance and move laterally. The activity is often part of a larger attack chain focused on compromising multiple systems. Defenders should monitor for unusual uses of `netsh.exe`, especially those involving firewall modifications related to network discovery. This technique allows compromised systems to identify other potential targets on the network.

## Attack Chain

1. An attacker gains initial access to a Windows host (e.g., via phishing or exploiting a vulnerability).
2. The attacker executes `netsh.exe` with administrative privileges.
3. `netsh.exe` is used to modify the Windows Firewall configuration.
4. The specific command executed is `netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes`.
5. This command enables Network Discovery, allowing the compromised host to send and receive network broadcast messages.
6. The attacker uses the enabled Network Discovery to identify other systems on the same network segment.
7. The attacker uses discovered hosts for lateral movement or further exploitation.
8. The final objective is often data theft, ransomware deployment, or establishing persistence within the network.

## Impact

Enabling Network Discovery via `netsh.exe` weakens a host's defenses and allows attackers to more easily identify and target other systems on the network. While the direct impact of this single action may be limited, it facilitates subsequent stages of an attack, potentially leading to widespread compromise, data exfiltration, or ransomware deployment. This activity has been observed in multiple incidents and can affect organizations of any size.

## Recommendation

*   Deploy the Sigma rule to detect the use of `netsh.exe` to enable Network Discovery (see rule: "Detect Netsh Enabling Network Discovery").
*   Investigate any instances of `netsh.exe` being used to modify firewall settings, particularly those related to the "Network Discovery" group.
*   Review and harden Windows Firewall configurations across the environment to restrict unnecessary network discovery.
*   Monitor process execution events for `netsh.exe` with process creation logs, specifically looking for command-line arguments related to firewall modifications.
