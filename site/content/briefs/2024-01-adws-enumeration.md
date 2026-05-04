---
title: Potential Enumeration via Active Directory Web Service
slug: 2024-01-adws-enumeration
description: Adversaries may abuse the Active Directory Web Service (ADWS) to enumerate network resources and user accounts, by loading AD-related modules followed by a network connection to the ADWS dedicated TCP port.
date: "2024-01-31T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - active-directory
  - enumeration
  - adws
  - discovery
  - windows
vendors:
  - Microsoft
products:
  - Active Directory Web Service
mitre_ttps:
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
references:
  - https://github.com/FalconForceTeam/SOAPHound
  - https://attack.mitre.org/techniques/T1018/
  - https://attack.mitre.org/techniques/T1069/
  - https://attack.mitre.org/techniques/T1069/002/
  - https://attack.mitre.org/techniques/T1087/
  - https://attack.mitre.org/techniques/T1087/002/
rules:
  - title: Potential ADWS Enumeration via Suspicious Library Loading
    description: Detects suspicious processes loading Active Directory related DLLs, which could indicate an attempt to enumerate ADWS.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
      - T1069
      - T1087
    data_sources:
      - image_load
      - windows
  - title: Potential ADWS Enumeration via Network Connection
    description: Detects network connections to the ADWS port (9389) from unusual processes, potentially indicating ADWS enumeration.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
      - T1069
      - T1087
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Active Directory Web Service (ADWS) facilitates querying Active Directory (AD) over a network, providing a web-based interface for directory services. Adversaries may exploit ADWS to enumerate network resources and user accounts, gaining insights into the environment. This attack involves loading Active Directory related modules and establishing network connections to the ADWS dedicated TCP port 9389. The goal is to gather information about the domain, user accounts, and permissions, which can be used for lateral movement, privilege escalation, and data exfiltration. Detection focuses on identifying suspicious processes loading `System.DirectoryServices*.dll` or `System.IdentityModel*.dll` and then connecting to the ADWS port.

## Attack Chain

1. An attacker gains initial access to a compromised host within the target network.
2. The attacker executes a reconnaissance tool or script (e.g., PowerShell) on the compromised host.
3. The reconnaissance tool loads Active Directory related modules such as `System.DirectoryServices*.dll` and `System.IdentityModel*.dll`.
4. The reconnaissance tool attempts to establish a network connection to the ADWS service on TCP port 9389, the dedicated port for ADWS.
5. The tool queries ADWS to retrieve information about domain users (T1087.002), groups (T1069.002), systems (T1018), and permissions.
6. The attacker analyzes the gathered information to identify privileged accounts and potential targets for lateral movement.
7. The attacker uses the discovered information to move laterally within the network.
8. The attacker escalates privileges, and exfiltrates sensitive data.

## Impact

Successful exploitation allows attackers to gain detailed knowledge of the Active Directory environment. This information can be used to identify high-value targets, compromise privileged accounts, move laterally within the network, and ultimately achieve their objectives, which could include data theft, ransomware deployment, or disruption of services. The impact can range from data breaches to complete compromise of the Active Directory domain, depending on the attacker's goals and the level of access they achieve.

## Recommendation

*   Deploy the Sigma rule "Potential ADWS Enumeration via Suspicious Library Loading" to detect processes loading AD-related DLLs (e.g., `System.DirectoryServices*.dll`, `System.IdentityModel*.dll`).
*   Deploy the Sigma rule "Potential ADWS Enumeration via Network Connection" to monitor for network connections to destination port 9389 from unusual processes.
*   Review and whitelist legitimate administrative tools or scripts that load Active Directory-related modules and connect to the ADWS port as described in the "False positive analysis" section of the original rule documentation.
*   Implement network segmentation to limit access to the ADWS port (9389) to only trusted systems and users.
