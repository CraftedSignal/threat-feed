---
title: Detection of Attacker Tools on Endpoints
slug: 2024-01-attacker-tools-on-endpoint
description: This analytic detects the execution of attacker tools used for unauthorized access, network scanning, privilege escalation, password dumping, or data exfiltration, based on process activity data from EDR agents and focusing on known attacker tool names.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - attacker-tool
  - endpoint
  - privilege-escalation
  - data-exfiltration
vendors:
  - Splunk
  - Cisco
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Cisco Network Visibility Module
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/attacker_tools_on_endpoint.yml
rules:
  - title: Attacker Tools Execution Detected
    description: Detects the execution of known attacker tools based on process name.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Attacker Tools Execution Detected - CommandLine
    description: Detects the execution of known attacker tools based on process command line.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection focuses on identifying the execution of tools commonly used by cybercriminals on endpoints. The detection leverages process activity data from Endpoint Detection and Response (EDR) agents, examining process names against a list of known attacker tools. The goal is to provide an early warning system for potential security incidents such as unauthorized access, data theft, or further network compromise. The analytic considers tools used for network scanning, privilege escalation, and password dumping. The detection logic relies on the "attacker_tools" lookup table to match observed process names against known malicious tools.

## Attack Chain

1.  An attacker gains initial access to a system (e.g., via phishing or exploiting a vulnerability).
2.  The attacker executes a reconnaissance tool (e.g., `nmap`, `masscan`) to scan the local network for potential targets and open ports.
3.  The attacker uses a privilege escalation tool (e.g., a Metasploit module, or a publicly available exploit) to gain elevated privileges on the compromised system.
4.  The attacker executes a credential dumping tool (e.g., `mimikatz`) to extract passwords and other credentials from memory.
5.  The attacker uses lateral movement techniques (e.g., pass-the-hash, pass-the-ticket) to move to other systems on the network.
6.  The attacker deploys additional attacker tools on other endpoints within the network.
7.  The attacker uses data exfiltration tools (e.g., `rsync`, `scp`) or techniques (e.g., steganography) to steal sensitive data.
8.  The attacker achieves their final objective, such as data theft, ransomware deployment, or system disruption.

## Impact

A successful attack involving the execution of attacker tools on endpoints can lead to severe consequences. This includes unauthorized access to sensitive data, data theft, further network compromise, and potential ransomware deployment. Organizations may experience financial losses, reputational damage, and legal liabilities. The impact extends to compromised Windows hosts, as well as potential lateral movement leading to compromise of critical assets.

## Recommendation

*   Ingest process GUID, process name, parent process, and command-line execution logs from EDR agents into Splunk as outlined in the "how_to_implement" section of the content.
*   Utilize the Splunk Common Information Model (CIM) to normalize field names and speed up data modeling to properly map data to the `Endpoint` data model as outlined in the "how_to_implement" section of the content.
*   Deploy the Sigma rule "Attacker Tools Execution Detected" to identify the execution of known attacker tools based on process name, tuning the "attacker_tools" lookup for your environment.
*   Add administrator accounts to the filter macro `attacker_tools_on_endpoint_filter` to reduce false positives, as outlined in the "known_false_positives" section of the content.
*   Investigate detections triggered by this analytic, focusing on the processes identified and their parent processes, to determine the scope and severity of the potential security incident as described in the "description" field.
