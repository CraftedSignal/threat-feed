---
title: AMSI Bypass via PowerShell Reflection
slug: 2024-01-amsi-bypass-reflection
description: Detection of AMSI (Antimalware Scan Interface) tampering via PowerShell reflection, utilizing PowerShell Script Block Logging (EventCode=4104) to identify commands manipulating `system.management.automation.amsi`, potentially leading to undetected malicious code execution and system compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - amsi-bypass
  - powershell
  - reflection
  - defense-evasion
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.1/add-other-data-to-splunk-uba/configure-powershell-logging-to-see-powershell-anomalies-in-splunk-uba.
  - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
  - https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/59c1814829f18782e24f1fe2/1505853768977/Windows+PowerShell+Logging+Cheat+Sheet+ver+Sept+2017+v2.1.pdf
  - https://www.crowdstrike.com/blog/investigating-powershell-command-and-script-logging/
rules:
  - title: Detect AMSI Unloading via PowerShell Reflection
    description: Detects attempts to bypass AMSI by using PowerShell reflection to access and modify the `system.management.automation.amsi` object.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect AMSI Unloading via PowerShell Script Block Logging
    description: Detects attempts to unload AMSI via PowerShell reflection based on script block logging (EventCode=4104).
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on detecting attempts to bypass the Antimalware Scan Interface (AMSI) by using PowerShell reflection. AMSI is a crucial security feature in Windows that allows applications and services to request malware scans of potentially malicious scripts and code. Attackers often attempt to disable or bypass AMSI to execute malicious payloads without being detected by security solutions. This particular technique leverages PowerShell's ability to interact with .NET objects via reflection to manipulate the AMSI provider and effectively disable it. The use of `system.management.automation.amsi` within PowerShell scripts is a strong indicator of this behavior. Detecting this activity is critical as it allows malicious scripts to run undetected, potentially leading to system compromise, data exfiltration, or other malicious activities.

## Attack Chain

1.  Attacker gains initial access to the system (e.g., via phishing or exploiting a vulnerability).
2.  The attacker executes a PowerShell script.
3.  The PowerShell script uses reflection to access the `system.management.automation.amsi` object.
4.  The script modifies the AMSI provider to disable scanning or return false negatives.
5.  The attacker executes malicious code (e.g., malware, ransomware) via PowerShell.
6.  Because AMSI is disabled, the malicious code is not scanned or detected.
7.  The attacker performs further actions, such as privilege escalation, lateral movement, or data exfiltration.
8.  The attacker achieves their objective, such as deploying ransomware or stealing sensitive data.

## Impact

Successful exploitation of this technique can lead to complete system compromise, as AMSI is a critical defense against script-based attacks. Depending on the attacker's objectives, impacts can range from data theft and ransomware deployment to persistent backdoor installation and disruption of services. Organizations using vulnerable PowerShell configurations may experience widespread malware infections and significant data loss. If left undetected, this technique can allow attackers to operate undetected for extended periods, increasing the potential for severe damage.

## Recommendation

*   Enable PowerShell Script Block Logging (EventCode 4104) to capture and analyze PowerShell commands. See the provided references for configuration details.
*   Deploy the provided Sigma rule `Detect AMSI Unloading via PowerShell Reflection` to your SIEM to detect the use of `system.management.automation.amsi` in PowerShell scripts.
*   Filter out known false positives from third-party applications as needed, based on your environment.
*   Monitor for unexpected PowerShell processes spawning from unusual parent processes, as this may indicate malicious activity.
*   Implement application control policies to restrict the execution of unsigned or untrusted PowerShell scripts.
