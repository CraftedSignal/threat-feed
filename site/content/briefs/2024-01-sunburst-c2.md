---
title: SUNBURST Command and Control Activity Detected
slug: 2024-01-sunburst-c2
description: This rule detects post-exploitation command and control activity related to the SUNBURST backdoor, which targets SolarWind's Orion software, mimicking the Orion Improvement Program (OIP) protocol for covert communication.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - APT29
  - Cozy Bear
  - NOBELIUM
  - UNC2452
  - Midnight Blizzard
  - The Dukes
tags:
  - solarwinds
  - sunburst
  - supply-chain
  - command-and-control
vendors:
  - SolarWinds
products:
  - SolarWinds Orion Platform
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
rules:
  - title: Detect SUNBURST C2 Activity via HTTP Body
    description: Detects SUNBURST C2 activity by monitoring HTTP requests from SolarWinds processes with specific content in the request body.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1195.002
    data_sources:
      - network_connection
      - windows
  - title: Detect SUNBURST related processes
    description: Detects SUNBURST related processes involved in network activity
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1195.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The SUNBURST malware, attributed to UNC2452, is a sophisticated supply chain attack targeting SolarWinds Orion business software. The trojanized SolarWinds.Orion.Core.BusinessLayer.dll plugin contains a backdoor that establishes command and control (C2) communication via HTTP to third-party servers. After a dormant period of up to two weeks, SUNBURST retrieves and executes commands, enabling file transfer, file execution, system profiling, system reboot, and service disabling. The malware disguises its network traffic to resemble legitimate SolarWinds activity by imitating the Orion Improvement Program (OIP) protocol. SUNBURST also uses obfuscated blocklists to evade forensic and anti-virus tools. This activity was observed starting in early 2020 and impacted numerous organizations globally.

## Attack Chain

1.  **Initial Compromise:** The attacker compromises the SolarWinds Orion software build process, injecting the SUNBURST backdoor into the SolarWinds.Orion.Core.BusinessLayer.dll plugin.
2.  **Deployment:** The compromised SolarWinds Orion software is deployed to target organizations as a routine software update.
3.  **Dormant Period:** The SUNBURST backdoor remains dormant for up to two weeks after initial deployment to evade immediate detection.
4.  **Beaconing:** After the dormant period, SUNBURST begins beaconing to command and control (C2) servers, mimicking OIP protocol behavior over HTTP.
5.  **Command Execution:** The C2 server delivers commands to the SUNBURST backdoor, instructing it to perform actions such as file transfer, execution, and system profiling.
6.  **Data Exfiltration:** SUNBURST exfiltrates sensitive data from the compromised system to the C2 server.
7.  **Lateral Movement:** Attackers leverage the compromised SolarWinds Orion server to move laterally within the victim's network.
8.  **Persistence:** The backdoor stores persistent state data within legitimate plugin configuration files for continued access.

## Impact

The SUNBURST attack compromised numerous organizations across various sectors, including government, technology, and telecommunications. Successful attacks resulted in the exfiltration of sensitive data, potential intellectual property theft, and disruption of critical services. The compromise affected over 18,000 SolarWinds customers who installed the trojanized Orion software updates. The financial impact of the SUNBURST attack is estimated to be in the tens of millions of dollars due to incident response, remediation, and reputational damage.

## Recommendation

*   Deploy the Sigma rule "Detect SUNBURST C2 Activity via HTTP Body" to your SIEM to identify suspicious network connections mimicking the OIP protocol (references: rule).
*   Deploy the Sigma rule "Detect SUNBURST related processes" to identify SolarWinds processes involved in suspicious network activity (references: rule).
*   Review and harden SolarWinds Orion installations, ensuring they are updated to the latest versions to prevent reinfection (references: references).
*   Monitor network traffic for connections to non-standard SolarWinds domains and IPs, investigating any anomalies (references: references).
*   Examine process execution chains for SolarWinds processes to identify any unknown or unexpected parent processes (references: references).
