---
title: Active Directory Discovery via ADExplorer Execution
slug: 2024-01-adexplorer-execution
description: Detects the execution of ADExplorer, a tool used for Active Directory viewing and editing, which can be abused by adversaries for domain reconnaissance and creating offline snapshots of the AD database.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - active-directory
  - discovery
  - reconnaissance
  - windows
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Microsoft Defender XDR
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
  - https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
rules:
  - title: Detect ADExplorer Execution via Process Name
    description: Detects the execution of ADExplorer based on the process name.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
  - title: Detect ADExplorer Execution via Original File Name
    description: Detects the execution of ADExplorer based on the process's original file name.
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

ADExplorer is an advanced Active Directory (AD) viewer and editor, it includes the ability to save snapshots of an AD database for offline viewing and comparisons. Adversaries may abuse this utility to perform domain reconnaissance, gather sensitive information about the AD structure, user accounts, and group memberships. The execution of ADExplorer is a potential indicator of malicious activity, especially when observed in environments where its use is not typical or when executed by unauthorized users. This activity can lead to further exploitation, such as privilege escalation and lateral movement within the network.

## Attack Chain

1. An attacker gains initial access to a Windows system through various means (e.g., compromised credentials, phishing).
2. The attacker downloads the ADExplorer utility (ADExplorer.exe) to the compromised host.
3. The attacker executes ADExplorer.exe to begin enumeration of the Active Directory environment.
4. ADExplorer interacts with the Active Directory domain controllers, querying information about users, groups, computers, and organizational units.
5. The attacker may use ADExplorer to save snapshots of the AD database for offline analysis.
6. The attacker analyzes the gathered information to identify privileged accounts, critical assets, and potential vulnerabilities within the AD environment.
7. The attacker uses the discovered information to plan further attacks, such as lateral movement or privilege escalation.

## Impact

Successful execution of ADExplorer by malicious actors can lead to the discovery of sensitive information about the Active Directory environment. This information can be leveraged to facilitate lateral movement, privilege escalation, and data exfiltration. While the initial risk score is low, the reconnaissance activity enables follow-on attacks that can have severe consequences, potentially leading to full domain compromise.

## Recommendation

*   Implement the Sigma rule `Detect ADExplorer Execution via Process Name` to detect the execution of ADExplorer based on process name.
*   Implement the Sigma rule `Detect ADExplorer Execution via Original File Name` to detect the execution of ADExplorer based on the process's original file name.
*   Monitor process creation events on Windows endpoints for the execution of ADExplorer.exe or processes with an original file name of "AdExp" to detect potential reconnaissance activities.
*   Investigate and validate any execution of ADExplorer by non-administrator accounts.
*   Review ADExplorer use and restrict its usage to authorized personnel.
