---
title: 'Ransomware-as-a-Service (RaaS) Ecosystem: Affiliate Tradecraft and Initial Access Vectors'
slug: 2026-05-raas-ecosystem
description: Ransomware-as-a-service (RaaS) attacks leverage affiliates for initial access, persistence, and exfiltration, using varied techniques like compromised RDP, vulnerable VPNs, and rogue RMM tools, impacting multiple organizations in a single campaign.
date: "2026-05-20T20:54:02Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - ransomware
  - raas
  - initial-access
  - persistence
vendors:
  - Microsoft
  - SonicWall
products:
  - Remote Desktop Protocol
  - Microsoft SQL Server
  - SonicWall VPNs
  - ScreenConnect
  - TeamViewer
  - Bomgar
  - Chrome Remote Desktop
  - AnyDesk
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1021.001
    technique_name: 'Remote Services: Remote Desktop Protocol'
references:
  - https://www.huntress.com/blog/raas-ecosystem-ransomware-tradecraft
rules:
  - title: Detect Suspicious RMM Tool Execution
    description: Detects execution of known RMM tools (ScreenConnect, TeamViewer, AnyDesk) from unusual locations or with suspicious command-line arguments, potentially indicating unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Detect New User Account Creation
    description: Detects the creation of new user accounts, which may indicate a persistence attempt by threat actors after initial access.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Ransomware-as-a-service (RaaS) has become a prevalent model where ransomware operators manage the ransomware variant and infrastructure, while affiliates handle the intrusion, data theft, and deployment of the encryptor. This division of labor means that the ransomware family name does not reliably explain the intrusion's origin or the actions taken by the attacker within the victim's environment. Different affiliates employ diverse techniques for initial access, ranging from social engineering to exploiting exposed remote access services and leveraging pre-existing footholds acquired from initial access brokers (IABs). Notably, threat actors are increasingly abusing legitimate tools and pathways to blend in with normal activity. For instance, in 2025, threat actors targeted SonicWall VPNs before deploying Akira ransomware. The affiliate, and not the ransomware operator, often dictates the tradecraft, necessitating a broad defense strategy.

## Attack Chain

1. **Initial Access via RDP:** Threat actors gain initial access by exploiting weak or compromised Remote Desktop Protocol (RDP) credentials, enabling RDP via SMB protocol, or through Microsoft SQL Server (MSSQL).
2. **Exploitation of Vulnerable Edge Appliances:** Attackers target vulnerable edge appliances, such as SonicWall VPNs, to gain network access, as observed in Akira ransomware deployments in 2025.
3. **Compromise of RMM Tools:** Rogue Remote Monitoring and Management (RMM) tools like ScreenConnect, TeamViewer, or Bomgar are compromised, providing a foothold in the victim's environment.
4. **Persistence through New User Creation:** Threat actors create new user accounts on the compromised systems to ensure persistent access.
5. **Account Hiding:** Attackers hide newly created user accounts from the Welcome Screen visible via Terminal Services/RDP to evade detection.
6. **Installation of Remote Access Tools:** Additional RMM tools like Chrome Remote Desktop and AnyDesk are installed post-compromise to retain remote access to the system.
7. **Defense Evasion:** Threat actors attempt to evade detection by configuring Defender exclusions or employing more aggressive tactics like EDR and AV killers.
8. **Data Exfiltration:** Data is staged by consolidating and compressing it into encrypted archives using tools like 7-Zip before exfiltration from the compromised network.

## Impact

RaaS attacks can lead to significant operational disruptions, data breaches, and financial losses for victim organizations. The exploitation of legitimate tools and pathways makes detection challenging, allowing attackers to move laterally within the network and exfiltrate sensitive data. In MSP-centric environments, a single compromised RMM instance can provide access to numerous downstream victims, as seen in the April 2026 incident involving a dental software company, impacting dozens of organizations. Successful ransomware deployment results in encrypted files, demanding ransom payments for decryption keys and potentially leading to data leaks if the ransom is not paid.

## Recommendation

*   Monitor process creation events for suspicious RMM tool usage, such as `ScreenConnect.exe` or `TeamViewer.exe` launching from unusual locations or with unusual command-line arguments, using the "Detect Suspicious RMM Tool Execution" Sigma rule.
*   Implement network connection monitoring to detect RDP connections originating from unexpected sources or using non-standard ports to identify potential RDP compromise (T1021.001).
*   Enable and review Windows Security Event Logs for Event ID 4720 (A user account was created) to detect unauthorized user account creation, a common persistence technique (T1547.001).
*   Implement host-based intrusion detection systems (HIDS) to detect unusual file compression activity using `7-Zip`, indicative of data staging for exfiltration.
