---
title: Suspicious Microsoft HTML Application Child Process
slug: 2024-01-mshta-suspicious-child
description: Mshta.exe spawning a suspicious child process, such as cmd.exe or powershell.exe, indicates potential adversarial activity leveraging Mshta to execute malicious scripts and evade detection on Windows systems.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - mshta
  - windows
  - process-creation
vendors:
  - Microsoft
  - HP
  - Crowdstrike
  - SentinelOne
products:
  - Windows
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Mshta/
rules:
  - title: MSHTA Spawning Suspicious Process
    description: Detects MSHTA spawning a suspicious process like cmd, powershell, or certutil
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: MSHTA Spawning Executable from User Directory
    description: Detects MSHTA spawning executable from user directory
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Mshta.exe (Microsoft HTML Application Host) is a Windows utility used to execute HTML Applications (.hta files). Adversaries often abuse Mshta to execute malicious scripts and evade detection, as it is a signed Microsoft binary and can bypass application whitelisting. This activity typically involves Mshta spawning other processes like cmd.exe or powershell.exe to perform malicious actions. This behavior has been observed across various attack campaigns and is a common tactic used to deliver payloads, establish persistence, or perform lateral movement within a network. Defenders need to monitor Mshta.exe process creations and child processes to detect and prevent potential threats. The detection logic focuses on identifying specific child processes commonly associated with malicious activities, while excluding legitimate uses of Mshta, such as those related to HP printer software.

## Attack Chain

1. An attacker gains initial access via an unspecified method (e.g., phishing, drive-by download) that delivers a malicious HTA file.
2. The user executes the HTA file, which launches Mshta.exe to interpret and execute the embedded script.
3. The script within the HTA file spawns a suspicious child process, such as cmd.exe or powershell.exe, using `CreateProcess`.
4. The spawned process executes malicious commands or scripts to download additional payloads or perform reconnaissance.
5. Certutil.exe may be used to decode encoded payloads.
6. The attacker may use bitsadmin.exe to download files from remote servers.
7. PowerShell is used to execute malicious code directly in memory, bypassing file-based detections.
8. The attacker achieves their objective, such as establishing persistence, stealing credentials, or deploying ransomware.

## Impact

Successful exploitation can lead to a range of consequences, including malware infection, data theft, and system compromise. The impact can vary depending on the attacker's objectives, but it can result in significant financial losses, reputational damage, and disruption of business operations. While specific numbers of victims are not listed, this technique is widely used and can affect any organization that does not adequately monitor and restrict the use of Mshta.exe. The sectors targeted are broad, as this is a general-purpose technique applicable to various environments.

## Recommendation

*   Enable process creation logging and monitor for Mshta.exe spawning suspicious child processes to enable the "Suspicious Microsoft HTML Application Child Process" rule.
*   Implement the provided Sigma rule to detect Mshta.exe spawning cmd.exe, powershell.exe, certutil.exe, bitsadmin.exe, curl.exe, msiexec.exe, schtasks.exe, reg.exe, wscript.exe, or rundll32.exe to detect potential defense evasion.
*   Examine `process.command_line` and `process.parent.command_line` for suspicious arguments and file paths to further investigate potential malicious use of Mshta.
*   Monitor for executables running from user directories using the Sigma rule provided to identify potentially malicious processes spawned by Mshta.exe.
*   Investigate the parent process of Mshta.exe to determine the initial source of the HTA execution, focusing on browsers, email clients, and other potential delivery mechanisms.
*   Tune the provided Sigma rules for your environment to reduce false positives and ensure accurate detection of malicious activity.
