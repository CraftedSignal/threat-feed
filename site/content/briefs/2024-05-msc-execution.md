---
title: Unusual Execution via Microsoft Common Console File
slug: 2024-05-msc-execution
description: Adversaries may embed a malicious command in an MSC file in order to trick victims into executing malicious commands, leading to initial access and execution of arbitrary code.
date: "2024-05-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - execution
  - initial-access
  - windows
  - msc
vendors:
  - Microsoft
  - Mozilla
  - Google
  - SentinelOne
products:
  - Common Console File
  - Edge
  - Firefox
  - Chrome
  - Internet Explorer
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
references:
  - https://www.genians.co.kr/blog/threat_intelligence/facebook
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_initial_access_via_msc_file.toml
rules:
  - title: Suspicious MMC Child Process Execution
    description: Detects unusual child processes spawned by Microsoft Management Console (mmc.exe), indicative of malicious .msc file exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1218.003
    data_sources:
      - process_creation
      - windows
  - title: MMC Executing Scripting Host
    description: Detects mmc.exe spawning scripting hosts (wscript.exe, cscript.exe, mshta.exe) indicating potential malicious script execution
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1218.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly leveraging Microsoft Common Console (MSC) files to deliver malicious payloads. This technique involves embedding malicious commands within an MSC file and enticing victims to execute them, bypassing traditional security measures. The attack begins when a user opens a seemingly benign .msc file, which in turn executes a malicious child process. This approach is effective because MSC files are typically associated with legitimate system administration tools, making them less likely to be flagged by security software or arouse suspicion from users. This technique has been observed in various threat landscapes. It is important for defenders to monitor process execution and command-line arguments to detect and prevent such attacks.

## Attack Chain

1.  An attacker crafts a malicious .msc file containing an embedded command.
2.  The attacker delivers the .msc file to the victim via phishing or other social engineering tactics.
3.  The victim opens the .msc file, which is processed by `mmc.exe`.
4.  `mmc.exe` executes a child process based on the embedded command, such as `cmd.exe`, `powershell.exe`, or `mshta.exe`.
5.  The child process executes a malicious script or downloads further payloads.
6.  The downloaded payload may establish persistence, such as creating a scheduled task or modifying registry keys.
7.  The attacker gains initial access and control over the compromised system.
8.  The attacker performs lateral movement, data exfiltration, or other malicious activities.

## Impact

Successful exploitation allows attackers to gain initial access and execute arbitrary code on compromised systems. This can lead to data theft, system compromise, and further malicious activities such as ransomware deployment. The execution of arbitrary code can enable adversaries to install backdoors, steal credentials, and move laterally within the network.

## Recommendation

*   Monitor process execution for unusual child processes spawned by `mmc.exe` with command-line arguments ending in `.msc` using the "Unusual Execution via Microsoft Common Console File" Sigma rule.
*   Enable Sysmon process creation logging to ensure visibility into process relationships and command-line arguments, which is crucial for detecting this type of attack.
*   Review and tune the provided Sigma rules to reduce false positives based on your environment's legitimate usage of `.msc` files.
*   Implement application control policies to restrict the execution of unauthorized or unknown executables, mitigating the impact of successful exploitation.
*   Educate users about the risks of opening untrusted files, especially those received via email or downloaded from the internet, to reduce the likelihood of initial compromise.
