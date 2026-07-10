---
title: Command Execution via ForFiles Utility for Defense Evasion
slug: 2024-01-forfiles-indirect-execution
description: Adversaries are leveraging the Windows `forfiles` utility to proxy command execution, potentially bypassing security controls by using a trusted process, for defense evasion.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - indirect-command-execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Forfiles/
  - https://attack.mitre.org/techniques/T1202/
rules:
  - title: Detect Command Execution via ForFiles
    description: Detects attempts to execute commands via the forfiles Windows utility, which can be used to proxy execution via a trusted parent process.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious ForFiles Usage with PowerShell
    description: Detects the usage of forfiles.exe to execute commands proxied by PowerShell, indicating potential defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `forfiles` utility, a legitimate Windows tool, is being abused by threat actors to execute arbitrary commands indirectly. This technique allows them to bypass application control and potentially evade detection by security solutions that trust the `forfiles.exe` process. The attacks involve using `forfiles` with the `/c` or `-c` arguments to execute commands, effectively using `forfiles` as a proxy. This activity has been observed across multiple environments. Defenders should monitor for unexpected usages of `forfiles` with command execution arguments, especially when originating from unusual parent processes or user accounts.

## Attack Chain

1. An attacker gains initial access to a Windows system (e.g., via phishing or exploiting a vulnerability).
2. The attacker attempts to execute a malicious command.
3. Instead of directly executing the command, the attacker uses `forfiles.exe` to proxy the execution.
4. The attacker invokes `forfiles.exe` with the `/c` or `-c` argument followed by the command to be executed. For example: `forfiles /p C:\Windows\System32 /s /m notepad.exe /c "cmd /c calc.exe"`.
5. `forfiles.exe` executes the specified command through `cmd.exe`.
6. The malicious command performs actions such as downloading malware, modifying system settings, or establishing persistence.
7. The attacker achieves their objective, such as data exfiltration or establishing a remote access channel.

## Impact

Successful exploitation of this technique can lead to a variety of malicious outcomes. Attackers can bypass application control policies, execute arbitrary code, and potentially compromise the entire system. The impact ranges from malware installation to data theft and remote control of the compromised machine. This can lead to significant financial loss, reputational damage, and disruption of business operations.

## Recommendation

*   Deploy the Sigma rule "Detect Command Execution via ForFiles" to your SIEM and tune for your environment to detect malicious usages of `forfiles.exe`.
*   Monitor process creation events for `forfiles.exe` executing with the `/c` or `-c` arguments (see Sigma rule and log source).
*   Implement application control policies to restrict the execution of unauthorized or malicious executables (reference attack chain and overview).
*   Investigate any instances of `forfiles.exe` executing commands from unusual parent processes or user accounts (see Sigma rule and overview).
