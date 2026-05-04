---
title: Netsh Used to Enable Remote Desktop Protocol (RDP) in Windows Firewall
slug: 2024-01-netsh-rdp-enable
description: Adversaries may use the `netsh.exe` utility to enable inbound Remote Desktop Protocol (RDP) connections in the Windows Firewall, potentially allowing unauthorized remote access to compromised systems.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - lateral-movement
  - windows
  - netsh
  - rdp
vendors:
  - Microsoft
  - Elastic
  - CrowdStrike
  - SentinelOne
products:
  - Windows Firewall
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Crowdstrike
affected_os:
  - Windows
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
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_enable_inbound_rdp_with_netsh.toml
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/004/
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/001/
  - https://attack.mitre.org/tactics/TA0005/
  - https://attack.mitre.org/tactics/TA0008/
rules:
  - title: Remote Desktop Enabled in Windows Firewall by Netsh
    description: Detects the use of netsh.exe to enable inbound RDP connections in the Windows Firewall.
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
    description: Detects netsh.exe being used to modify firewall rules.
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

Attackers can leverage the native Windows command-line tool `netsh.exe` to modify Windows Firewall rules and enable inbound Remote Desktop Protocol (RDP) connections. This can be used as a defense evasion technique to bypass existing firewall restrictions, allowing them to establish remote access to a compromised host. Ransomware operators and other malicious actors frequently utilize RDP to access victim servers, often using privileged accounts, to further their objectives. This activity can be conducted post-compromise to facilitate lateral movement and the deployment of malicious payloads. The behavior was observed being detected by Elastic Defend, Microsoft Defender XDR, SentinelOne Cloud Funnel, and Crowdstrike.

## Attack Chain

1. An attacker compromises a Windows host through initial access methods (e.g., phishing, exploitation of a vulnerability).
2. The attacker gains a foothold on the system and escalates privileges as needed.
3. The attacker executes `netsh.exe` with specific arguments to modify the Windows Firewall configuration.
4. The `netsh` command creates or modifies an inbound rule to allow RDP traffic (TCP port 3389).
5. The attacker establishes an RDP connection to the compromised host.
6. The attacker uses the RDP session to perform reconnaissance, move laterally, or deploy malware.
7. The attacker may attempt to disable or modify security tools to further evade detection.
8. The attacker achieves their objective, such as data exfiltration or ransomware deployment.

## Impact

Successful exploitation of this technique can lead to unauthorized remote access to systems, enabling lateral movement, data theft, and ransomware deployment. If RDP is enabled on a large number of systems, the attacker can move laterally through the environment. The impact can range from data breaches to complete operational disruption.

## Recommendation

*   Monitor process creation events for `netsh.exe` executing with arguments related to enabling inbound RDP traffic using the "Remote Desktop Enabled in Windows Firewall by Netsh" rule.
*   Implement the Sigma rule provided below to detect instances of `netsh.exe` being used to modify firewall rules related to RDP.
*   Enforce the principle of least privilege and restrict the use of `netsh.exe` to authorized personnel only.
*   Review existing firewall rules and remove any unnecessary or overly permissive rules.
*   Enable Sysmon process creation logging for enhanced visibility into process execution events.
