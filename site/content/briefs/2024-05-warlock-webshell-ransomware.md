---
title: Warlock Group Deploys Web Shells, Tunnels, and Ransomware
slug: 2024-05-warlock-webshell-ransomware
description: The Warlock group utilizes web shells and tunneling to deploy ransomware within compromised environments, impacting victim data confidentiality and availability.
date: "2026-03-19T05:26:28Z"
type: coverage
types:
  - coverage
severities:
  - critical
actors:
  - Warlock
tags:
  - webshell
  - ransomware
  - tunneling
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1572
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rxruun/web_shells_tunnels_and_ransomware_dissecting_a/
  - https://www.trendmicro.com/en_us/research/26/c/dissecting-a-warlock-attack.html
rules:
  - title: Detect Web Shell Creation
    description: Detects the creation of common web shell file extensions in web server directories.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - windows
  - title: Detect Web Server Tunneling Activity
    description: Detects network connections from web servers to uncommon ports, indicative of tunneling.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This brief describes a Warlock attack, as detailed in a Trend Micro analysis, involving the use of web shells, tunneling, and ransomware deployment. The Warlock group compromises systems by leveraging web shells for initial access and establishing tunnels for persistent access and command and control. This access is then used to deploy ransomware, encrypting critical data and demanding ransom payments from victims. The specific ransomware family and web shell variants employed are not detailed in the provided context, but the overall attack flow is consistent with financially motivated cybercrime operations. Defenders should prioritize detection of web shell activity, unauthorized tunneling, and ransomware execution to mitigate the risk of compromise by the Warlock group.

## Attack Chain

1. **Initial Access:** The attacker gains access to the target system by exploiting vulnerabilities to deploy a web shell (details of the vulnerability are not provided).
2. **Web Shell Execution:** The attacker executes commands through the web shell to perform reconnaissance and identify valuable targets within the network.
3. **Tunnel Establishment:** A tunnel is established to maintain persistent access and bypass security controls (specific tunneling technology not provided).
4. **Lateral Movement:** The attacker leverages the established tunnel to move laterally within the network, compromising additional systems.
5. **Credential Access:** The attacker attempts to harvest credentials to gain elevated privileges and access to critical resources (specific tools/techniques not provided).
6. **Ransomware Deployment:** The attacker deploys ransomware across the network, encrypting files and rendering systems unusable.
7. **Ransom Demand:** A ransom note is left on the compromised systems, demanding payment for decryption keys.
8. **Data Exfiltration (Possible):** Prior to encryption, the attacker may exfiltrate sensitive data to further pressure victims into paying the ransom (not explicitly stated, but a common practice).

## Impact

The Warlock attack results in significant disruption to victim organizations through ransomware deployment. Systems are rendered unusable due to encryption, potentially leading to operational downtime and financial losses. If data exfiltration occurs, the confidentiality of sensitive information is also compromised, increasing the potential for reputational damage and legal liabilities. The lack of specific victim counts and sector targeting data in the provided context limits a comprehensive impact assessment.

## Recommendation

*   Deploy a web shell detection rule (see below) to identify suspicious web shell activity on web servers based on process creation.
*   Implement a network monitoring rule (see below) to detect unusual tunneling activity based on network connections from web servers.
*   Enable file integrity monitoring to detect unauthorized modifications to web server files that could indicate web shell installation (reference file_event log source).
