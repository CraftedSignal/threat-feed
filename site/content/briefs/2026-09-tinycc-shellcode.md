---
title: Abuse of TinyCC Compiler for Shellcode Execution
slug: 2026-09-tinycc-shellcode
description: The Lotus Blossom Chrysalis backdoor campaign leverages the Tiny C Compiler (TinyCC) to execute shellcode in memory by masquerading the compiler binary as a system process.
date: "2026-09-04T18:01:59Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lotus Blossom
tags:
  - windows
  - execution
  - defense-evasion
  - fileless
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The technique was observed in the Lotus Blossom Chrysalis backdoor campaign, where attackers renamed tcc.exe to svchost.exe, and executed a file named conf.c containing Metasploit block_api shellcode.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: TinyCC is a legitimate C compiler, but its ability to compile and execute code on-the-fly makes it attractive to attackers seeking to evade detection.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: where tcc.exe is renamed to masquerade as svchost.exe and used to compile and execute C source files containing shellcode.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1027/
  - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
rules:
  - title: Detect Renamed TinyCC Compiler Execution
    description: Detects TinyCC (tcc.exe) masquerading as svchost.exe using specific compiler flags for in-memory execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for TinyCC execution masquerading as svchost.
      owner: Detection Engineering
      due: 48h
      evidence: Source provided specific command-line arguments and process naming convention used by the threat actor.
  hunt_leads:
    - lead: Search for process execution where Image name is svchost.exe but OriginalFileName is tcc.exe.
      technique_id: T1036
      data_needed:
        - Endpoint process creation logs with metadata
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Renaming tcc.exe to svchost.exe is a core component of this TTP.
  mitigation_plan:
    - priority: medium_term
      action: Restrict execution of compilers from user-writable directories (Temp, AppData) via AppLocker or WDAC.
      owner: IT Operations
      addresses: T1059.003
      evidence: Compiler execution from non-standard locations is a primary indicator of this threat.
---

The Lotus Blossom Chrysalis backdoor campaign has been observed utilizing the Tiny C Compiler (TinyCC) as a vehicle for in-memory shellcode execution. Attackers rename the legitimate 'tcc.exe' binary to 'svchost.exe' to masquerade as a critical Windows system process, allowing them to evade basic process monitoring. By invoking the renamed binary with specific command-line arguments ('-nostdlib' and '-run') on user-provided C source files (e.g., 'conf.c'), the attackers compile and execute malicious code, such as Metasploit block_api shellcode, directly in memory. This technique is particularly effective for defenders as it facilitates fileless execution from non-standard directory locations like AppData or Temp, bypassing typical static signature-based detection. Because TinyCC is a legitimate compiler, its misuse is best identified by monitoring for process masquerading and the use of compilation flags outside of expected developer environments.

## Attack Chain

1. Attacker drops the legitimate 'tcc.exe' compiler binary into a non-standard, user-writable directory.
2. Attacker renames the binary to 'svchost.exe' to mimic a native Windows system process.
3. Attacker drops a malicious C source code file (e.g., 'conf.c') containing embedded shellcode into the same directory.
4. Attacker executes the renamed 'svchost.exe' (tcc.exe) via command line, passing the source file as an argument.
5. Attacker includes the '-nostdlib' flag to ignore standard libraries and '-run' to execute the code in memory immediately.
6. The TinyCC binary compiles the malicious C file on-the-fly and loads the resulting shellcode directly into memory.
7. The shellcode executes, providing the attacker with persistent C2 capabilities or further stage loading without ever writing a standalone executable to disk.

## Impact

The use of this technique allows for the stealthy execution of malware within compromised environments. It enables the Chrysalis backdoor to maintain persistence and execute arbitrary malicious payloads in memory, significantly complicating forensic analysis and incident response. The capability to execute shellcode filelessly helps the actor maintain a low footprint, potentially avoiding detection by EDR tools that primarily scan for file-based malicious activity.

## Recommendation

Prioritize detection engineering and defensive measures centered on process masquerading and unusual compiler usage.
- Implement detection for process renaming where the 'OriginalFileName' attribute of a process does not match its running name (e.g., 'svchost.exe' with an original file name of 'tcc.exe').
- Enable Sysmon Event ID 1 logging globally and ensure full command-line arguments are captured in telemetry to enable the detection of the '-nostdlib' and '-run' flags.
- Baseline execution patterns for 'tcc.exe' in the environment to differentiate between legitimate development activities and malicious usage from non-standard locations.
- Deploy the provided Sigma rule to alert on suspicious TinyCC usage originating from outside standard system or developer directories.
