---
title: Windows OpenSSH Client Used for Indirect Command Execution
slug: 2024-01-openssh-proxy-execution
description: Attackers are leveraging the Windows OpenSSH client (ssh.exe, sftp.exe) to proxy command execution and bypass application controls by executing commands such as powershell, schtasks, or cmd, indicating a defense evasion attempt.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - proxy-execution
  - openssh
  - windows
vendors:
  - Microsoft
products:
  - OpenSSH Client
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1202
    technique_name: Indirect Command Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ssh/
  - https://attack.mitre.org/techniques/T1202/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Proxy Execution via Windows OpenSSH
    description: Detects attempts to execute commands via proxy using the Windows OpenSSH client with suspicious command line arguments.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
  - title: OpenSSH Client Proxying CMD Execution
    description: Detects indirect command execution via OpenSSH client using cmd.exe
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

Attackers are abusing the legitimate Windows OpenSSH client (ssh.exe and sftp.exe) to proxy command execution, a technique known as "Indirect Command Execution" (T1202). This method allows adversaries to bypass application control solutions by leveraging trusted binaries already present on the system. By embedding malicious commands within the OpenSSH command line arguments, attackers can execute arbitrary code, escalate privileges, and establish persistence while blending in with legitimate system activity. This technique is particularly effective because OpenSSH is often trusted and permitted to run without restriction. The observed commands of interest include powershell, schtasks, @echo off, http, mshta, msiexec, cmd /c, cmd.exe, and scp which commonly are used in malicious activities.

## Attack Chain

1. An attacker gains initial access to a Windows system via an exploit, phishing, or stolen credentials.
2. The attacker leverages the built-in OpenSSH client (ssh.exe or sftp.exe).
3. The attacker crafts a command line argument for ssh.exe or sftp.exe that includes a malicious command to be executed indirectly.
4. The malicious command is embedded within the command line, utilizing keywords such as `Command=powershell`, `schtasks`, `Command=@echo off`, `Command=http`, `Command=mshta`, `Command=msiexec`, `Command=cmd /c`, `Command=cmd.exe`, `LocalCommand=scp*&&*`, `LocalCommand=?scp*&&*`, or `Command=*script*`.
5. The OpenSSH client executes the malicious command, bypassing application control restrictions.
6. The attacker uses the executed command to download and execute malware, establish persistence, or gather sensitive information.
7. The attacker moves laterally to other systems on the network, repeating steps 2-6.
8. The attacker achieves their final objective, such as data exfiltration or ransomware deployment.

## Impact

Successful exploitation leads to arbitrary code execution, privilege escalation, and persistence within the targeted environment. Bypassing application control measures allows attackers to introduce malware and compromise critical systems. This can result in data breaches, financial losses, and reputational damage. The broad use of OpenSSH makes many Windows systems vulnerable.

## Recommendation

*   Deploy the Sigma rule "Proxy Execution via Windows OpenSSH" to detect suspicious command line arguments passed to ssh.exe and sftp.exe (reference: rules section).
*   Monitor process creation events for ssh.exe and sftp.exe with command lines containing keywords such as powershell, schtasks, @echo off, http, mshta, msiexec, cmd /c, cmd.exe, and scp (reference: rules section).
*   Review and harden application control policies to prevent execution of unauthorized or unexpected commands through OpenSSH (reference: Overview section).
*   Enable Sysmon process creation logging to capture the necessary command-line details for effective detection (reference: rules section).
