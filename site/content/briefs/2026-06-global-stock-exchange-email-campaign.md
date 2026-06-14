---
title: Global Stock Exchange Hit by Monthslong Email Campaign
slug: 2026-06-global-stock-exchange-email-campaign
description: An unknown threat actor gained continuous administrative access to a senior finance executive's Microsoft Outlook mailbox at a global stock exchange for at least five months, deploying custom infostealers via scheduled tasks and exfiltrating sensitive emails through a Dropbox-based command and control channel after an initial lateral movement event.
date: "2026-06-14T09:38:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - espionage
  - financial-sector
  - email-exfiltration
  - persistence
  - living-off-the-land
  - windows
  - advanced-persistent-threat
vendors:
  - Microsoft
products:
  - Microsoft Outlook
  - Microsoft OneDrive
  - Adobe software
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://www.darkreading.com/cyberattacks-data-breaches/global-stock-exchange-hit-monthslong-email-campaign
rules:
  - title: Detect Suspicious Scheduled Task for Persistence
    description: Detects the creation of scheduled tasks with names or actions indicative of attacker persistence, such as masquerading as system health checks or legitimate software like Adobe/OneDrive.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1036.005
      - T1053.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Process Masquerading as Legitimate Software
    description: Detects processes running from unusual locations or with names that mimic legitimate software like Adobe or OneDrive, indicative of implant deployment.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.005
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Network Connection to Dropbox from Suspicious Processes
    description: Identifies outbound network connections to Dropbox services originating from processes that are not typically associated with legitimate cloud synchronization or from suspicious paths, indicative of C2 or exfiltration.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1071.001
      - T1567.002
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

An unidentified threat actor successfully conducted a sophisticated and patient email espionage campaign targeting a senior finance executive at an unnamed global stock exchange. The campaign began with observed lateral movement on October 10, 2025, suggesting a prior network compromise. The attacker maintained a near-continuous view into the executive's Microsoft Outlook inbox for at least five months, from August 2025 until the last observed activity on March 19, 2026. This was achieved by deploying persistent implants disguised as legitimate software (Adobe, OneDrive) with system privileges via scheduled tasks. A custom infostealer, leveraging the legitimate Aspose .NET library, was used to convert emails into local files, which were then exfiltrated through a Dropbox-based command and control channel designed to mimic legitimate network traffic. The strategic targeting of a major financial exchange indicates an objective to acquire highly sensitive, non-public information with significant potential value to businesses, investors, or foreign governments.

## Attack Chain

1.  **Lateral Movement**: Initial observed activity on October 10, 2025, stemmed from lateral movement originating from a previously compromised device, indicating the attacker already had a foothold within the network.
2.  **Implant Deployment**: Two implants were deployed to the compromised host, disguised as legitimate Adobe and OneDrive software, both executing with system privileges.
3.  **Persistence (Scheduled Task)**: The Adobe-like implant was registered as a scheduled task, configured to execute every five minutes to ensure continuous persistence on the compromised host.
4.  **Command and Control Setup**: On November 12, 2025, the attackers established a command-and-control (C2) channel utilizing Dropbox, aiming for exfiltrated data to appear as legitimate cloud service traffic.
5.  **Enhanced Persistence & Execution**: A new scheduled task was registered to execute batch files, meticulously disguised as an ordinary Lenovo system health check, demonstrating intimate knowledge of the target's machine.
6.  **Infostealer Deployment**: A custom infostealer, built using a legitimate Aspose .NET library, was deployed to specifically target and collect the executive's emails.
7.  **Data Collection & Staging**: The infostealer converted the target's emails into local files. The attacker initially siphoned all emails from August to mid-November 2025.
8.  **Exfiltration & Recurrent Collection**: The collected email files were exfiltrated via the Dropbox C2 channel. The attacker repeatedly stole the entire email inbox every two to four weeks until February 17, 2026.

## Impact

The prolonged access to a senior finance executive's email inbox at a global stock exchange resulted in the continuous exfiltration of highly sensitive, non-public information for at least five months. This included intimate details about the organization, contacts, calendar events, and specific business deals. Given the nature of a major financial exchange, this intelligence could hold significant value for competitive businesses, investors, or even foreign governments, potentially leading to market manipulation, corporate espionage, or severe financial losses for affected entities. The specific number of affected individuals is one executive, but the strategic value of the compromised information is substantial.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM and tune them for your environment to detect suspicious scheduled task creation and process masquerading.
*   Implement a Cloud Access Security Broker (CASB) and Data Loss Prevention (DLP) solution to monitor and prevent unauthorized data exfiltration to cloud services like Dropbox.
*   Ensure Endpoint Detection and Response (EDR) software is actively monitoring for and generating alerts on suspicious process activity, and establish processes for prompt review and response to these alerts.
*   Enable Sysmon logging for process creation (Event ID 1), scheduled task creation (Event ID 12, 13, 14, 21), and network connections (Event ID 3) to capture telemetry required by the detection rules.
