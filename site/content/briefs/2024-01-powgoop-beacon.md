---
title: MuddyWater PowGoop Beacon Decoding Detection
slug: 2024-01-powgoop-beacon
description: This detection identifies a DLL decoding and executing the PowGoop config.txt payload, indicating a stage in the MuddyWater infection chain where an obfuscated PowerShell beacon is unwrapped and live C2 communication starts.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - MuddyWater
tags:
  - muddywater
  - powgoop
  - dll-sideloading
  - powershell
  - c2
  - beacon
vendors:
  - Google
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Google Update
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://www.cisa.gov/uscert/sites/default/files/publications/AA22-055A_Iranian_Government-Sponsored_Actors_Conduct_Cyber_Operations.pdf
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_powgoop_beacon_decoding.yml
rules:
  - title: Detect Windows PowGoop Beacon Decoding via CommandLine
    description: Detects PowGoop beacon decoding activity by monitoring the command line parameters of PowerShell processes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Windows PowGoop Beacon Decoding via Parent Process
    description: Detects PowGoop beacon decoding activity by monitoring parent processes associated with PowerShell decoding activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The detection identifies a specific stage in the MuddyWater (also known as SeedWorm, Static Kitten, and MERCURY) infection chain, focusing on the execution of the PowGoop loader. MuddyWater has been actively using PowGoop since at least 2020 as their primary initial access method. PowGoop abuses DLL side-loading, specifically targeting a fake GoogleUpdate.exe, to initiate a multi-stage decoding process. This ultimately leads to the deployment of a fully functional PowerShell backdoor disguised with a benign extension. The backdoor uses a config.txt file that contains a hardcoded C2 address and victim GUID. The malware beacons via modified base64-encoded HTTP, attempting to blend C2 traffic with legitimate Google Update processes to evade network-based detections.

## Attack Chain

1. Initial access is achieved through an unknown vector (e.g., spearphishing) leading to the execution of a malicious DLL.
2. The malicious DLL is sideloaded by a fake GoogleUpdate.exe, masquerading as a legitimate Google application.
3. The DLL initiates a multi-stage decoding chain to decrypt and execute a PowerShell script.
4. The PowerShell script reads a `config.txt` file containing a hardcoded C2 address and victim GUID.
5. The PowerShell script decodes the C2 address from the config file to establish command and control.
6. PowerShell uses FromBase64String to decode the payload.
7. The PowerShell backdoor establishes persistence and begins beaconing to the C2 server via modified base64-encoded HTTP requests.
8. The attacker uses the established C2 channel to perform reconnaissance, lateral movement, and data exfiltration.

## Impact

A successful PowGoop infection allows MuddyWater to gain persistent access to the compromised system. This access can be leveraged for a variety of malicious activities, including data theft, espionage, and further propagation of malware within the network. MuddyWater has been linked to numerous cyber espionage campaigns targeting government and commercial entities, particularly in the Middle East. The group's activities pose a significant risk to organizations seeking to protect sensitive information and maintain operational integrity.

## Recommendation

*   Enable Sysmon Event ID 1 (process creation) logging to capture the necessary process execution details for the Sigma rules provided.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Investigate any PowerShell processes spawned by rundll32.exe that decode base64 strings and reference `config.txt`, as highlighted in the rule "Detect Windows PowGoop Beacon Decoding via CommandLine".
*   Monitor network traffic for base64-encoded HTTP requests originating from the Google Update process, as this is a technique used by PowGoop to mask C2 communications.
