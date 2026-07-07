---
title: Permission Check Via Accesschk.EXE
slug: 2026-07-accesschk-permission-check
description: Attackers are abusing the legitimate Sysinternals `Accesschk.exe` utility to perform permission discovery on Windows systems, a common step in privilege escalation attacks, allowing them to identify misconfigurations for gaining higher privileges.
date: "2026-07-03T14:25:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sysinternals
  - privilege-escalation
  - tool-abuse
  - discovery
  - windows
vendors:
  - Microsoft
products:
  - Accesschk
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: Detects the usage of the 'Accesschk' utility, an access and privilege audit tool developed by SysInternal and often being abused by attacker to verify process privileges
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_sysinternals_accesschk_check_permissions.yml
  - https://speakerdeck.com/heirhabar/hunting-for-privilege-escalation-in-windows-environment?slide=43
  - https://www.youtube.com/watch?v=JGs-aKf2OtU&ab_channel=OFFZONEMOSCOW
  - https://github.com/carlospolop/PEASS-ng/blob/fa0f2e17fbc1d86f1fd66338a40e665e7182501d/winPEAS/winPEASbat/winPEAS.bat
  - https://github.com/gladiatx0r/Powerless/blob/04f553bbc0c65baf4e57344deff84e3f016e6b51/Powerless.bat
rules:
  - title: Permission Check Via Accesschk.EXE
    description: Detects the usage of the 'Accesschk' utility to verify process privileges and system permissions, often abused by attackers for privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Adversaries are leveraging the legitimate Microsoft Sysinternals utility `Accesschk.exe` to perform reconnaissance and permission checking on compromised Windows systems. This tool, originally designed for system administrators to audit permissions, is a favored binary for threat actors due to its native capabilities and often being pre-trusted by security solutions. Its abuse enables attackers to quickly identify misconfigurations, weak permissions, or unquoted service paths on files, directories, registry keys, services, and processes. This information is crucial for planning subsequent privilege escalation techniques, allowing an attacker to move from a low-privileged foothold to administrative or system-level access, thereby advancing their objectives such as persistence, lateral movement, or data exfiltration.

## Attack Chain

1.  **Initial Compromise**: An attacker gains initial access to a target Windows system, typically through methods like phishing, exploiting a vulnerable service, or compromising credentials.
2.  **Tool Staging**: The `Accesschk.exe` utility (or its 64-bit variants like `accesschk64.exe`) is transferred to the compromised system, often via existing C2 channels, PowerShell, or embedded within a larger malicious payload.
3.  **Permission Discovery**: The attacker executes `Accesschk.exe` from a command prompt or script using specific flags such as `uwcqv` (users with write access to services), `kwsu` (kernel objects, services, users), or `uwdqs` (users with write access to directories/shares) to enumerate detailed permissions across various system objects.
4.  **Output Analysis**: The command output is parsed by the attacker to identify specific misconfigurations or weak access control lists (ACLs) that could be exploited. This might include writable service binaries, DLL hijack paths, or modifiable registry keys.
5.  **Identify Escalation Paths**: Based on the gathered permission data, the attacker pinpoints viable privilege escalation vectors, such as services configured to run with SYSTEM privileges but having a writable binary path, or registry keys that control critical system functions and are modifiable by low-privileged users.
6.  **Exploitation Planning**: The attacker formulates a strategy to exploit the identified weaknesses, which could involve replacing legitimate binaries with malicious ones, modifying service parameters, or injecting code into processes to achieve higher privileges.
7.  **Privilege Escalation**: The attacker executes their chosen method to elevate privileges, often resulting in gaining administrator or SYSTEM-level access on the compromised host.
8.  **Post-Escalation Actions**: With elevated privileges, the attacker can proceed with further malicious activities, including deploying additional malware, establishing persistence, moving laterally within the network, or exfiltrating sensitive data.

## Impact

Successful abuse of `Accesschk.exe` as part of a privilege escalation chain can lead to full system compromise, allowing attackers to gain complete control over the affected Windows machine. This enables them to bypass security controls, install rootkits, steal credentials, deploy ransomware, or exfiltrate critical intellectual property and sensitive data. While `Accesschk.exe` itself doesn't cause direct damage, its role in uncovering vulnerabilities can directly lead to significant security breaches, financial loss, reputational damage, and operational disruption for affected organizations across all sectors.

## Recommendation

*   Deploy the Sigma rule `Permission Check Via Accesschk.EXE` to your SIEM and tune for your environment to detect suspicious usage of this utility.
*   Ensure Sysmon process creation logging is enabled for all Windows endpoints to capture `Image` and `CommandLine` details necessary for the rule `Permission Check Via Accesschk.EXE`.
*   Regularly audit permissions on critical system resources and services to identify and remediate misconfigurations that `Accesschk.exe` could reveal to an attacker.
