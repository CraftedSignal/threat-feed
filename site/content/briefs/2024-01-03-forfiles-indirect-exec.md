---
title: Command Execution via ForFiles Utility
slug: 2024-01-03-forfiles-indirect-exec
description: Adversaries may use the Windows forfiles utility to proxy command execution via a trusted parent process, potentially evading detection.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - indirect-execution
  - windows
vendors:
  - Microsoft
  - CrowdStrike
  - SentinelOne
  - Elastic
products:
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Elastic Defend
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Forfiles/
rules:
  - title: Command Execution via ForFiles
    description: Detects attempts to execute commands using the forfiles Windows utility, which can be used to proxy execution via a trusted parent process.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: ForFiles Execution from Suspicious Path
    description: Detects forfiles.exe executing from a non-standard path, indicating potential malicious activity.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows `forfiles` utility is a legitimate command-line tool that allows batch processing of files. However, adversaries can abuse `forfiles` to execute arbitrary commands indirectly, bypassing security controls and evading detection. This technique, known as "Indirect Command Execution," involves using `forfiles` to invoke other processes or run scripts, effectively hiding the malicious intent behind a trusted Windows utility. This method can be used to download payloads, execute scripts, or perform other malicious activities under the guise of legitimate `forfiles` activity. The attacks leveraging this technique have been observed since at least 2025. This matters for defenders because it allows attackers to blend in with normal system activity and makes it harder to identify malicious behavior.

## Attack Chain

1. An attacker gains initial access to the system through an unknown vector (e.g., phishing or exploiting a vulnerability).
2. The attacker leverages `forfiles.exe` to execute a command by using the `/c` or `-c` argument.
3. The attacker crafts the command to execute a script, download a file, or perform another malicious action.
4. `forfiles.exe` launches the specified command, which could involve PowerShell, cmd.exe, or another scripting engine.
5. The script executes, downloading a malicious payload from an external source.
6. The payload is saved to disk and executed, establishing persistence.
7. The attacker uses the compromised system to move laterally within the network.
8. The final objective is achieved, such as data exfiltration or ransomware deployment.

## Impact

Successful exploitation can lead to a compromised system, allowing attackers to perform various malicious activities, including data theft, malware installation, and lateral movement within the network. The impact is dependent on the attacker's objectives and the level of access gained. By using `forfiles`, attackers can bypass traditional security measures and remain undetected for longer periods. The severity is medium as it requires initial access and relies on a dual-use tool.

## Recommendation

*   Deploy the Sigma rule `Command Execution via ForFiles` to your SIEM to detect suspicious command execution patterns involving `forfiles.exe`.
*   Monitor process creation events for instances of `forfiles.exe` with the `/c` or `-c` arguments, excluding known legitimate uses as specified in the Sigma rule.
*   Investigate any instances of `forfiles.exe` execution where the command line contains suspicious parameters or attempts to execute scripts from unusual locations (e.g., the user's temporary directory).
*   Enable Sysmon process creation logging (Event ID 1) to gain more detailed information about process executions, including command-line arguments and parent-child relationships.
*   Review and audit the usage of `forfiles.exe` across the environment to identify any unauthorized or suspicious activity.
