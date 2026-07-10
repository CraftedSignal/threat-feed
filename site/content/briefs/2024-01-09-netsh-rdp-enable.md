---
title: Netsh Used to Enable Remote Desktop Protocol (RDP) in Windows Firewall
slug: 2024-01-09-netsh-rdp-enable
description: Adversaries use the `netsh.exe` utility to enable inbound Remote Desktop Protocol (RDP) connections through the Windows Firewall, potentially for unauthorized remote access and lateral movement.
date: "2024-01-09T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - lateral-movement
  - windows
  - rdp
vendors:
  - Microsoft
products:
  - Windows
  - Windows Firewall
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://attack.mitre.org/techniques/T1562/004/
  - https://attack.mitre.org/techniques/T1021/001/
rules:
  - title: Remote Desktop Enabled in Windows Firewall by Netsh
    description: Detects use of netsh.exe to enable inbound RDP connections in Windows Firewall.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1021.001
      - T1562.004
    data_sources:
      - process_creation
      - windows
  - title: Netsh Firewall Rule Modification
    description: Detects the modification of firewall rules via netsh.exe
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

Attackers can enable Remote Desktop Protocol (RDP) access by modifying the Windows Firewall configuration, using the native `netsh.exe` utility. This allows them to bypass existing firewall rules and gain unauthorized remote access to systems. Ransomware operators frequently leverage RDP for lateral movement and access to sensitive servers. Defenders should monitor for unusual use of `netsh.exe` to modify firewall settings, particularly those related to RDP. This activity can occur post-compromise to facilitate remote access and further exploitation. Identifying these changes early can prevent attackers from establishing a persistent foothold within the network.

## Attack Chain

1. An attacker gains initial access to a Windows system, possibly through credential theft or vulnerability exploitation.
2. The attacker executes `netsh.exe` with specific arguments to create or modify firewall rules.
3. The command targets the "Remote Desktop" firewall group.
4. The command modifies the firewall to allow inbound RDP traffic on local port 3389.
5. The attacker enables the newly created or modified firewall rule.
6. RDP is now enabled through the Windows Firewall, allowing connections from potentially unauthorized sources.
7. The attacker uses RDP to connect to the compromised system and perform further actions, such as lateral movement, data exfiltration, or ransomware deployment.

## Impact

Successful exploitation allows attackers to remotely access compromised systems, potentially leading to data theft, malware installation, or complete system compromise. If RDP is enabled on critical servers, this can disrupt business operations and cause significant financial loss. This technique can also enable lateral movement to other systems within the network.

## Recommendation

*   Monitor process creation events for `netsh.exe` with command-line arguments related to enabling inbound RDP connections using the Sigma rule provided.
*   Review Windows Firewall logs for newly created or modified rules allowing inbound RDP traffic.
*   Implement network segmentation to limit the scope of RDP access, restricting access to authorized users and systems.
*   Enforce multi-factor authentication (MFA) for RDP access to prevent unauthorized logins even if credentials are compromised.
*   Regularly audit and review Windows Firewall rules to identify and remove any unauthorized modifications.
*   Enable Sysmon process creation logging to activate the rules above.
