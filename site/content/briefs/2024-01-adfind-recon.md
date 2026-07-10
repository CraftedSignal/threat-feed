---
title: AdFind.exe Execution with Reconnaissance Arguments
slug: 2024-01-adfind-recon
description: This rule detects the execution of AdFind.exe with specific command-line arguments used for reconnaissance, often associated with threat actors like Wizard Spider, FIN6, and groups linked to SUNBURST, who use it to enumerate domain controllers.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
actors:
  - Conti
  - Wizard Spider
  - FIN6
  - SUNBURST associated actors
tags:
  - active-directory
  - reconnaissance
  - adfind
  - discovery
vendors:
  - JoeWare
  - Microsoft
  - SolarWinds
products:
  - AdFind
  - Active Directory
  - SolarWinds
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
references:
  - https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/
  - https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html
  - https://www.joeware.net/freetools/tools/adfind/usage.htm
iocs:
  - type: filename
    value: adfind.exe
ioc_counts:
  filename: 1
rules:
  - title: Detect AdFind Execution with Reconnaissance Parameters
    description: Detects execution of AdFind.exe with common reconnaissance parameters.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
  - title: Detect AdFind Execution with Domain Enumeration Arguments
    description: Detects execution of AdFind.exe with command line arguments that are used to enumerate domain information.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1018
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying the execution of `adfind.exe` with specific command-line arguments often employed for reconnaissance activities within Active Directory environments. `adfind.exe` is a legitimate command-line tool for querying Active Directory, but it can be abused by threat actors to gather information about users, computers, and other objects within the domain. This behavior has been observed in connection with threat actors like Wizard Spider, FIN6, and groups associated with the SUNBURST supply chain attack. The detection specifically targets processes involving command-line arguments like `-f`, `-b`, `objectcategory`, `-gcb`, and `-sc`, which are commonly used to filter and search for specific objects in Active Directory. The tool is often used to enumerate domain controllers to map the environment before lateral movement or privilege escalation.

## Attack Chain

1.  The attacker gains initial access to a compromised system within the target network.
2.  AdFind.exe is deployed to the compromised host.
3.  AdFind.exe is executed with specific command-line arguments to query Active Directory. The command includes parameters like `-f` or `-b` for filtering, and `objectcategory` to search for specific objects.
4.  The tool is executed with arguments like `-gcb` to query the Global Catalog or `-sc` to specify the search scope.
5.  AdFind.exe gathers information about domain controllers, users, groups, and other objects.
6.  The gathered information is parsed and analyzed by the attacker to identify potential targets and vulnerabilities.
7.  The attacker uses the gathered information to plan lateral movement, privilege escalation, or other malicious activities.
8.  The attacker leverages the collected intelligence to identify key assets for data exfiltration.

## Impact

Successful execution of AdFind.exe for reconnaissance can provide attackers with a comprehensive understanding of the Active Directory environment, facilitating lateral movement, privilege escalation, and data exfiltration. While the source doesn't specify the number of victims or targeted sectors, the tool's use by known threat actors like Wizard Spider and FIN6 suggests the potential for significant impact, including ransomware deployment, data theft, and business disruption. The SUNBURST example highlights the risk of supply chain compromises leading to widespread reconnaissance activities.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect suspicious AdFind.exe execution and tune for your environment.
*   Monitor process execution logs for instances of `adfind.exe` with command-line arguments like `-f`, `-b`, `objectcategory`, `-gcb`, and `-sc` (process field in the logs).
*   Implement network segmentation to limit the scope of potential reconnaissance activities.
*   Investigate any detected instances of AdFind.exe execution to determine the attacker's objectives and scope of compromise.
*   Enable Sysmon process-creation logging to activate the rules above.
