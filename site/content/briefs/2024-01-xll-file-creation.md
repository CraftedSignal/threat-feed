---
title: Detects Windows XLL File Creation Outside of Typical Location
slug: 2024-01-xll-file-creation
description: The creation of an XLL file outside of typical locations can indicate an attempt to abuse Excel COM objects to load and execute a malicious XLL payload, often used in spearphishing attacks to achieve remote code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - xll
  - excel
  - file_creation
  - endpoint
vendors:
  - Microsoft
  - Splunk
products:
  - Excel
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1129
    technique_name: Shared Modules
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.bleepingcomputer.com/news/security/new-specula-tool-uses-outlook-for-remote-code-execution-in-windows/
  - https://github.com/trustedsec/specula/wiki
rules:
  - title: XLL File Creation Outside of Typical Locations
    description: Detects the creation of an XLL file outside of typical locations, which can indicate an attempt to abuse Excel COM objects to load and execute a malicious XLL.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1129
    data_sources:
      - file_event
      - windows
  - title: XLL File Creation by Unusual Process
    description: Detects the creation of an XLL file by a process other than Excel itself, indicating potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1129
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers are known to leverage malicious Excel add-in files (.xll) to execute arbitrary code on a victim's machine. These files, when opened by Excel, can load and run malicious code embedded within them. The technique is often seen in spearphishing campaigns where a user is tricked into opening the malicious XLL file. This detection focuses on identifying XLL file creation events occurring outside of standard application or add-in directories, which is a strong indicator of potentially malicious activity. The goal is to detect the initial stage of the attack, preventing further exploitation.

## Attack Chain

1. A malicious XLL file is delivered to the victim, often via spearphishing attachment or download.
2. The victim opens the XLL file, potentially after being socially engineered.
3. Excel loads the XLL file.
4. The XLL file executes malicious code.
5. The malicious code may establish persistence through registry modifications or scheduled tasks.
6. The attacker gains initial access to the system.
7. The attacker executes arbitrary commands, downloads additional payloads, or moves laterally within the network.
8. The attacker achieves their final objective, such as data exfiltration or ransomware deployment.

## Impact

Successful exploitation can lead to complete system compromise, potentially affecting all data and applications on the compromised machine. This can lead to data breaches, financial loss, and reputational damage. Organizations in any sector are vulnerable, especially those with employees who handle email and Excel documents. The impact includes potential remote code execution, data theft, and lateral movement within the network.

## Recommendation

*   Enable Sysmon Event ID 11 (FileCreate) logging to capture file creation events on endpoints to support the provided rules.
*   Deploy the Sigma rule `XLL File Creation Outside of Typical Locations` to your SIEM and tune for your environment.
*   Investigate any identified events to determine whether the XLL file is malicious.
*   Educate users about the risks of opening unsolicited attachments and enabling macros.
*   Review and restrict Excel add-in installation policies to prevent unauthorized installations.
