---
title: Windows Delayed Execution via Ping Followed by Malicious Utilities
slug: 2024-01-delayed-execution-via-ping
description: Adversaries may use ping to delay execution of malicious commands, scripts, or binaries to evade detection, often observed during malware installation.
date: "2024-01-02T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - execution
  - defense-evasion
  - windows
  - ping
  - lolbas
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1216
    technique_name: System Script Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1220
    technique_name: XSL Script Processing
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1497
    technique_name: Virtualization/Sandbox Evasion
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_delayed_via_ping_lolbas_unsigned.toml
rules:
  - title: Delayed Execution via Ping
    description: Detects the execution of commonly abused Windows utilities via a delayed Ping execution.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.003
      - T1497.003
    data_sources:
      - process_creation
      - windows
  - title: Delayed Execution via Ping - AppData Execution
    description: Detects unsigned executable execution in AppData after ping delay.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may use ping to introduce pauses, allowing them to execute harmful scripts or binaries stealthily. This delayed execution is often observed during malware installation and is consistent with an attacker attempting to evade detection. The adversary uses `ping.exe` with the `-n` argument from within a `cmd.exe` shell, and the parent process is running under a user context other than SYSTEM. The subsequent process is `cmd.exe` invoking a known malicious utility, such as `powershell.exe`, `mshta.exe`, `rundll32.exe`, or an executable from the user's AppData directory without a valid code signature. This behavior is often observed during malware installation.

## Attack Chain

1.  The attack begins with an initial access vector (not specified in source).
2.  The adversary executes `cmd.exe`.
3.  `cmd.exe` spawns `ping.exe` with the `-n` argument to introduce a delay, typically to evade detection (`ping.exe -n [number] 127.0.0.1`).
4.  After the delay introduced by `ping.exe`, the same `cmd.exe` process executes a potentially malicious utility such as `powershell.exe`, `mshta.exe`, `rundll32.exe`, `certutil.exe`, or `regsvr32.exe`.
5.  Alternatively, `cmd.exe` might execute a binary located within the user's AppData directory that lacks a valid code signature.
6.  The malicious utility executes arbitrary commands or scripts, potentially downloading further payloads or modifying system configurations.
7.  The attacker gains a foothold on the system, enabling further malicious activities such as lateral movement or data exfiltration.

## Impact

A successful attack can lead to malware installation, system compromise, and data theft. While the source does not quantify the number of victims or specific sectors targeted, a successful compromise can lead to significant operational disruption and data breaches. The use of delayed execution makes it more difficult for traditional security solutions to detect malicious activity.

## Recommendation

*   Deploy the Sigma rule "Delayed Execution via Ping" to your SIEM to detect the execution of commonly abused Windows utilities via a delayed Ping execution.
*   Enable process monitoring with command-line argument logging to capture the execution of `ping.exe` and subsequent processes for analysis.
*   Implement application whitelisting to prevent unauthorized execution of scripts and binaries, focusing on the utilities identified in the rule.
*   Review and tune the provided Sigma rule, including the listed exclusions, to reduce false positives in your specific environment.
*   Monitor process execution from unusual locations like the AppData directory, especially for unsigned executables, as indicated in the rule's detection logic.
