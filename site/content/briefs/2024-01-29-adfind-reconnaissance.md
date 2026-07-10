---
title: AdFind Active Directory Reconnaissance Activity
slug: 2024-01-29-adfind-reconnaissance
description: AdFind.exe, a legitimate Active Directory query tool, is commonly abused by threat actors such as Trickbot, Ryuk, Maze, and FIN6 for post-exploitation Active Directory reconnaissance, enabling enumeration of objects like computers, people, subnets, and domain information.
date: "2024-01-29T12:00:00Z"
type: threat
types:
  - threat
severities:
  - low
actors:
  - Trickbot
  - Ryuk
  - Maze
  - FIN6
tags:
  - adfind
  - active-directory
  - reconnaissance
  - discovery
  - windows
vendors:
  - Microsoft
products:
  - Active Directory
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
references:
  - http://www.joeware.net/freetools/tools/adfind/
  - https://thedfirreport.com/2020/05/08/adfind-recon/
  - https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html
  - https://www.cybereason.com/blog/dropping-anchor-from-a-trickbot-infection-to-the-discovery-of-the-anchor-malware
  - https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html
  - https://usa.visa.com/dam/VCOM/global/support-legal/documents/fin6-cybercrime-group-expands-threat-To-ecommerce-merchants.pdf
rules:
  - title: AdFind Computer Enumeration
    description: Detects AdFind execution with arguments to enumerate computer objects.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1018
      - T1087.002
    data_sources:
      - process_creation
      - windows
  - title: AdFind Domain Information Discovery
    description: Detects AdFind execution with arguments to enumerate domain information.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016
      - T1482
    data_sources:
      - process_creation
      - windows
  - title: AdFind Group Enumeration
    description: Detects AdFind execution with arguments to enumerate Active Directory groups.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1069.002
      - T1087.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

AdFind is a command-line tool used to query and retrieve information from Active Directory (AD). While AdFind has legitimate uses for network administrators, threat actors frequently leverage it to perform post-exploitation Active Directory reconnaissance. This tool allows for the quick discovery and enumeration of AD objects, subnets, and domain information. AdFind has been observed in campaigns involving Trickbot, Ryuk, Maze, and FIN6. Defenders should monitor for its execution with specific arguments indicative of reconnaissance activity. The rule focuses on identifying AdFind execution based on process name and command-line arguments related to object category enumeration and domain information gathering.

## Attack Chain

1. Initial access is achieved through an exploit, compromised credentials, or other means (not described in source).
2. The attacker establishes a foothold on a compromised system within the network.
3. AdFind.exe is deployed to the compromised host, either as a standalone executable or as part of a larger toolset.
4. The attacker executes AdFind.exe with command-line arguments to enumerate Active Directory objects, such as computers (objectcategory=computer), users (objectcategory=person), or organizational units (objectcategory=organizationalunit).
5. The attacker queries for domain information, including domain lists (domainlist), domain controller modes (dcmodes), and domain controller lists (dclist) using AdFind.
6. Information gathered is used to map out the Active Directory structure and identify high-value targets.
7. Lateral movement is initiated based on the identified targets, using gathered credentials or exploiting vulnerabilities.
8. The final objective could be data exfiltration, ransomware deployment, or other malicious activities within the compromised environment.

## Impact

Successful reconnaissance using AdFind allows attackers to map out the Active Directory environment, identify critical assets, and plan further attacks. This can lead to lateral movement, data theft, ransomware deployment, and significant disruption to business operations. While the tool itself is benign, its use in conjunction with specific parameters by malicious actors allows them to quickly identify critical resources such as privileged accounts and domain controllers.

## Recommendation

*   Deploy the Sigma rules provided to your SIEM to detect AdFind execution with reconnaissance-related arguments, and tune for your environment.
*   Enable Sysmon process creation logging to capture the necessary process execution data for the provided Sigma rules.
*   Review process execution logs for instances of AdFind.exe and analyze command-line arguments to identify potentially malicious activity.
*   Investigate any alerts triggered by the Sigma rules in conjunction with other security events on the affected host.
