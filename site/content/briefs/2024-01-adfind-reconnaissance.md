---
title: AdFind Tool Used for Active Directory Reconnaissance
slug: 2024-01-adfind-reconnaissance
description: The execution of AdFind.exe, an Active Directory query tool, is often used by threat actors for post-exploitation Active Directory reconnaissance, as observed in campaigns involving Trickbot, Ryuk, Maze, and FIN6.
date: "2024-01-02T12:00:00Z"
type: threat
types:
  - threat
severities:
  - low
actors:
  - FIN6
tags:
  - adfind
  - active-directory
  - reconnaissance
  - windows
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
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
  - title: AdFind Command Activity
    description: Detects the execution of AdFind.exe with command-line arguments indicative of Active Directory reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
  - title: AdFind Original Filename Activity
    description: Detects AdFind execution based on PE original filename metadata.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

AdFind is a command-line tool used to retrieve information from Active Directory. While it has legitimate uses for network administrators, threat actors frequently leverage it for post-exploitation Active Directory reconnaissance. The tool allows for quick scoping of AD person/computer objects and understanding subnets and domain information. AdFind has been observed in campaigns associated with various threat actors, including Trickbot, Ryuk, Maze, and FIN6. This reconnaissance activity is typically conducted after initial compromise to gather information for lateral movement and privilege escalation. The detection of AdFind execution, especially with specific command-line arguments, can indicate malicious activity within a compromised environment.

## Attack Chain

1. Initial Access: An attacker gains initial access to a Windows host, possibly through exploitation of a vulnerability or compromised credentials.
2. Tool Transfer: The attacker transfers AdFind.exe to the compromised host.
3. Execution: The attacker executes AdFind.exe from the command line or via a script.
4. Discovery: AdFind is used to enumerate Active Directory objects such as computers (`objectcategory=computer`), users (`objectcategory=person`), subnets (`objectcategory=subnet`), and groups (`objectcategory=group`).
5. Information Gathering: The attacker gathers information about domain controllers using commands such as `dclist` or `dcmodes`.
6. Privilege Escalation: The gathered information is used to identify potential targets for privilege escalation, such as accounts with weak passwords or misconfigured permissions.
7. Lateral Movement: The attacker uses the gathered information to move laterally to other systems within the network.
8. Objective Completion: The attacker achieves their final objective, such as data exfiltration or ransomware deployment.

## Impact

Successful reconnaissance using AdFind can provide attackers with a comprehensive understanding of the Active Directory environment, facilitating lateral movement, privilege escalation, and ultimately, the exfiltration of sensitive data or deployment of ransomware. While the use of AdFind itself may not be directly damaging, it is a strong indicator of malicious activity within a compromised network. The impact can range from data breaches and financial losses to reputational damage and disruption of business operations.

## Recommendation

*   Deploy the Sigma rule "AdFind Command Activity" to your SIEM to detect the execution of AdFind with suspicious command-line arguments.
*   Enable Sysmon process-creation logging to provide the necessary data for the Sigma rule to function effectively (reference the Sysmon setup documentation).
*   Investigate any alerts generated by the "AdFind Command Activity" Sigma rule to determine the scope and impact of the potential compromise.
*   Monitor process execution events for AdFind-related activity, focusing on command-line arguments used to query Active Directory objects (reference the `query` field in the original rule).
*   Implement network segmentation to limit the scope of potential lateral movement following a successful compromise.
