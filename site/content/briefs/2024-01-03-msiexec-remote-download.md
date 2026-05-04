---
title: Suspicious MSIExec Remote Download
slug: 2024-01-03-msiexec-remote-download
description: The analytic detects the execution of msiexec.exe with an HTTP or HTTPS URL, which indicates an attempt to download and execute potentially malicious software from a remote server, leading to potential unauthorized code execution, system compromise, or malware deployment.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - endpoint
  - msiexec
  - remote-download
  - windows
vendors:
  - Microsoft
  - Cisco
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network Visibility Module
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.007/T1218.007.md
rules:
  - title: Detect MSIExec Remote Download via CommandLine
    description: Detects msiexec.exe executing with a command line containing an HTTP or HTTPS URL, indicating a remote file download attempt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
  - title: Detect MSIExec Remote Download via Parent Process
    description: Detects msiexec.exe executing with a parent process that is not a standard Windows process, downloading an MSI from the internet.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The detection focuses on identifying instances where `msiexec.exe` is used with an HTTP or HTTPS URL in the command line. This behavior is indicative of an attempt to download and execute potentially malicious software from a remote server. The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant as it may indicate an attempt to download and execute potentially malicious software from a remote server. If confirmed malicious, this could lead to unauthorized code execution, system compromise, or further malware deployment within the network. The activity is often used to bypass traditional security controls.

## Attack Chain

1. An attacker gains initial access through various means, such as phishing or exploiting a software vulnerability.
2. The attacker leverages `msiexec.exe`, a legitimate Windows utility, to download a malicious MSI package from a remote HTTP or HTTPS server.
3. The command line includes a URL pointing to a malicious MSI file hosted on a compromised or attacker-controlled server.
4. `msiexec.exe` downloads the MSI package to the victim's machine.
5. The MSI package is executed, potentially installing malware, creating new files, or modifying system settings.
6. The installed malware establishes persistence through registry keys or scheduled tasks.
7. The malware initiates command and control (C2) communication to receive further instructions.
8. The attacker performs actions on the objective such as data exfiltration or lateral movement within the compromised network.

## Impact

Successful exploitation can lead to unauthorized code execution, system compromise, or further malware deployment within the network. The use of `msiexec.exe` for remote downloads can bypass traditional security controls, allowing attackers to deliver and execute malicious payloads undetected. The dfirreport.com article references data exfiltration following exploitation via MSIExec.

## Recommendation

*   Enable Sysmon process-creation logging to activate the rules below, capturing command-line details (Sysmon EventID 1).
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Monitor network traffic for connections originating from `msiexec.exe` to external HTTP/HTTPS URLs (Network Visibility Module Flow Data).
*   Investigate any instances of `msiexec.exe` executing with command-line arguments containing HTTP or HTTPS URLs.
*   Filter false positives by destination or parent process as needed based on your environment.
