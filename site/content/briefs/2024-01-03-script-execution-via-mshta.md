---
title: Script Execution via Microsoft HTML Application
slug: 2024-01-03-script-execution-via-mshta
description: Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries by using rundll32.exe or mshta.exe to execute scripts via HTML applications.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - script-execution
  - mshta
vendors:
  - Microsoft
products:
  - HTML Application
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/techniques/T1218/011/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/005/
  - https://attack.mitre.org/techniques/T1059/007/
rules:
  - title: Suspicious Mshta Execution with Script Keywords
    description: Detects mshta.exe executing with command lines containing suspicious script keywords indicative of malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.005
      - T1059.007
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: Mshta Execution from Downloads Directory
    description: Detects mshta.exe being executed with a command line pointing to a file within the user's Downloads directory, a common location for downloaded malicious files.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: Rundll32 Script Execution
    description: Detects rundll32.exe executing with command lines that contain script-like arguments.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.005
      - T1059.007
      - T1218.011
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers leverage Microsoft HTML Applications (HTA) to execute scripts in a trusted environment, often using `rundll32.exe` or `mshta.exe`, to evade defenses. This technique, observed in various campaigns since at least 2020, involves proxying malicious script execution through signed binaries, making detection challenging. The scope of this threat extends to any Windows environment where users can execute HTML applications. Defenders must monitor for suspicious command-line arguments and parent-child process relationships involving `mshta.exe` and `rundll32.exe`.

## Attack Chain

1.  The user downloads a malicious HTA file, often disguised as a legitimate document, from a phishing email or compromised website.
2.  The user executes the downloaded HTA file, which triggers the execution of `mshta.exe`.
3.  `mshta.exe` interprets and executes the embedded script within the HTA file.
4.  The script may contain obfuscated or encoded commands to evade detection.
5.  The script utilizes techniques such as `GetObject`, `WScript.Shell`, or `RegWrite` to perform malicious actions.
6.  `mshta.exe` executes commands to download and execute additional payloads.
7.  The downloaded payloads establish persistence, escalate privileges, and perform lateral movement.
8.  The final objective includes data exfiltration, deploying ransomware, or establishing a persistent backdoor.

## Impact

Successful exploitation can lead to complete system compromise, data theft, and ransomware deployment. Affected systems can be leveraged for further attacks within the network, impacting all connected devices. Victims may experience significant financial losses, reputational damage, and operational disruption. The broad scope of Windows environments makes this a widespread threat, particularly affecting organizations that rely on user-executed scripts and applications.

## Recommendation

*   Monitor process execution for `rundll32.exe` and `mshta.exe` with command-line arguments containing suspicious script-related keywords using the Sigma rules provided.
*   Investigate instances of `mshta.exe` executing from common download locations such as the `Downloads` folder, as highlighted in the rule logic.
*   Implement application control policies to restrict the execution of unsigned or untrusted HTA files.
*   Audit and review parent-child process relationships involving `mshta.exe` and `rundll32.exe` to identify anomalous behavior.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
