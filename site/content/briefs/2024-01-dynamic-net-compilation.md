---
title: Suspicious Dynamic .NET Compilation via Csc.exe
slug: 2024-01-dynamic-net-compilation
description: Attackers may use csc.exe to compile .NET code on the fly to evade detection, often placing the compiler and source code in suspicious locations, which can be detected by monitoring process creation events.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - defense-evasion
  - dynamic-compilation
  - csc.exe
vendors:
  - Microsoft
products:
  - .NET Framework
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/
  - https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf
  - https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/
  - https://twitter.com/gN3mes1s/status/1206874118282448897
  - https://github.com/redcanaryco/atomic-red-team/blob/b27a3cb25025161d49ac861cb216db68c46a3537/atomics/T1027.004/T1027.004.md#atomic-test-1---compile-after-delivery-using-cscexe
rules:
  - title: Detect Csc.exe from Suspicious Locations
    description: Detects the execution of csc.exe from suspicious directories often used by attackers to evade detection.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1027.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Csc.exe Compiling from User Favorites/Contacts/Pictures
    description: Detects csc.exe compiling code where the source files are located in user profile directories like Favorites or Contacts, which is suspicious.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1027.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often utilize the .NET Framework's command-line compiler, `csc.exe`, to compile malicious code dynamically on compromised systems. This tactic allows them to evade traditional signature-based detections and execute code in memory. The compilation often occurs from unusual or temporary directories such as `\Perflogs\`, `\Users\Public\`, or within the `AppData` directory. This technique has been observed in campaigns involving malware such as Agent Tesla and by actors like MuddyWater. Detection focuses on identifying `csc.exe` executions originating from or utilizing paths indicative of suspicious activity outside of normal software development workflows.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the system through an exploit or social engineering.
2.  Payload Delivery: A malicious payload containing .NET source code is delivered to the system, often dropped in a temporary directory or a user's profile directory.
3.  Command Execution: The attacker uses a command-line interface (cmd.exe or powershell.exe) to execute `csc.exe`.
4.  Dynamic Compilation: `csc.exe` compiles the .NET source code into an executable or DLL file.
5.  File Creation: The compiled assembly is written to disk in a specified location.
6.  Code Injection/Execution: The compiled assembly is loaded into memory and executed, often using techniques like reflective DLL injection.
7.  Persistence (Optional): The attacker may establish persistence by creating a scheduled task or modifying registry keys to recompile and execute the malicious code on system startup.
8.  Achieve Objectives: The attacker achieves their objectives, such as data exfiltration, lateral movement, or establishing a command and control channel.

## Impact

Successful exploitation can lead to arbitrary code execution, allowing attackers to perform a wide range of malicious activities. This can result in data theft, system compromise, and the deployment of ransomware. While the number of victims and sectors targeted varies depending on the specific campaign, dynamic compilation techniques significantly increase the difficulty of detection and response, making systems vulnerable to persistent and stealthy attacks.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect suspicious executions of `csc.exe` from unusual locations (process_creation logs).
*   Tune the Sigma rules for your environment to reduce false positives, considering legitimate uses of `csc.exe` by developers (Sigma rules).
*   Monitor process creation events for `csc.exe` with command-line arguments containing suspicious directory locations like `\Perflogs\`, `\Users\Public\`, `\AppData\Local\Temp\` (process_creation logs).
*   Investigate any instances where `csc.exe` is executed by processes other than legitimate software development tools, filtering out known good parent processes like `sdiagnhost.exe` or `w3wp.exe` (process_creation logs).
*   Consider blocking execution of `csc.exe` from user-writable directories if it is not a legitimate use case in your environment.
