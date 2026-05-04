---
title: UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer
slug: 2024-01-03-uac-bypass-ieinstal
description: This threat brief details a UAC bypass technique leveraging the Internet Explorer Add-On Installer (ieinstal.exe) and Component Object Model (COM) to execute arbitrary code with elevated privileges.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - uac-bypass
  - privilege-escalation
  - com
  - ieinstal
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Elastic Defend
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Inter-Process Communication
references:
  - https://swapcontext.blogspot.com/2020/11/uac-bypasses-from-comautoapprovallist.html
rules:
  - title: UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer
    description: Detects UAC bypass attempts using ieinstal.exe and a malicious executable in a temporary directory.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - privilege_escalation
    techniques:
      - T1218
      - T1548.002
      - T1559.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Executed from Temp Directory with ieinstal.exe as Parent
    description: Detects processes running from a temporary directory, launched by ieinstal.exe, indicating a potential UAC bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - privilege_escalation
    techniques:
      - T1218
      - T1548.002
      - T1559.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies a User Account Control (UAC) bypass technique that abuses the Internet Explorer Add-On Installer (ieinstal.exe) to launch malicious programs with elevated privileges. Attackers exploit elevated COM interfaces to circumvent UAC, allowing for stealthy code execution. The specific behavior involves executing a program from a temporary directory using ieinstal.exe with the `-Embedding` argument. This bypass can be utilized to perform various malicious activities, including installing malware, modifying system settings, or establishing persistence. The targeted systems are Windows endpoints where UAC is enabled. This technique matters because it allows attackers to gain unauthorized access with elevated permissions, undermining standard Windows security controls.

## Attack Chain

1.  The attacker gains initial access to the system, possibly through phishing or other means.
2.  The attacker drops a malicious executable into a temporary directory, such as `C:\Users\<user>\AppData\Local\Temp\IDC*.tmp\`.
3.  The attacker invokes `ieinstal.exe` with the `-Embedding` argument, specifying the path to the malicious executable.
4.  `ieinstal.exe`, running with elevated privileges, launches the malicious executable due to COM object handling.
5.  The malicious executable executes with elevated privileges, bypassing UAC prompts.
6.  The attacker leverages elevated privileges to perform malicious activities, such as installing malware or modifying system settings.
7.  The attacker establishes persistence to maintain elevated access across system reboots.

## Impact

Successful exploitation of this UAC bypass technique allows attackers to execute arbitrary code with elevated privileges, bypassing security controls designed to prevent unauthorized system modifications. This can lead to the installation of malware, data theft, or complete system compromise. The severity of the impact is high, as it grants attackers significant control over the affected system.

## Recommendation

*   Deploy the Sigma rule "UAC Bypass Attempt via Elevated COM Internet Explorer Add-On Installer" to your SIEM to detect potential UAC bypass attempts.
*   Enable Sysmon process creation logging to capture the necessary events for the Sigma rule to function correctly.
*   Monitor process execution from temporary directories, specifically those matching the pattern `C:\\*\\AppData\\*\\Temp\\IDC*.tmp\\*.exe`.
*   Investigate any instances of `ieinstal.exe` being executed with the `-Embedding` argument, as this is a key indicator of the UAC bypass attempt.
*   Implement application whitelisting to prevent unauthorized executables from running, particularly those in temporary directories.
