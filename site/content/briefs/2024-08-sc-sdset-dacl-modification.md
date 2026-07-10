---
title: Service DACL Modification via sc.exe
slug: 2024-08-sc-sdset-dacl-modification
description: Adversaries modify a service's DACL (Discretionary Access Control List) via `sc.exe` to deny access to key user groups, potentially making the service unstoppable or hiding it from users and the system, in order to evade defenses and persist.
date: "2024-08-13T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - persistence
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://blogs.jpcert.or.jp/en/2024/07/mirrorface-attack-against-japanese-organisations.html
  - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sc_sdset_deny_service_access.yml
  - https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
  - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
rules:
  - title: Service DACL Modification via sc.exe
    description: Detects DACL modifications to a service using sc.exe, potentially denying access and hindering management.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1543.003
      - T1564
    data_sources:
      - process_creation
      - windows
  - title: Service DACL Modification via sc.exe - Alternate Detection
    description: Detects DACL modifications to a service using sc.exe based on original file name, potentially denying access and hindering management.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1543.003
      - T1564
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can exploit the Windows `sc.exe` utility to modify service DACLs (Discretionary Access Control Lists), effectively denying access to specific user groups and system accounts. This activity, often employed as a defense evasion tactic, aims to render services unmanageable or conceal them from standard system administration tools. By manipulating DACLs, adversaries can prevent legitimate users and security software from interacting with or terminating malicious services. This technique is particularly concerning as it can lead to persistent malware execution and hinder incident response efforts. The behavior is seen across Windows environments, with attackers targeting access rights for built-in groups like IU (Interactive User), SU (Service User), BA (Built-in Administrators), SY (SYSTEM), and WD (All Users).

## Attack Chain

1.  The attacker gains initial access to the system through unspecified means (e.g., exploitation, social engineering).
2.  The attacker executes `sc.exe` with the `sdset` parameter, targeting a specific service.
3.  The attacker crafts the `sdset` command to modify the service's DACL, denying access to specific security principals. The command includes arguments like `D;` to specify denial ACEs.
4.  The DACL modification string includes access rights that explicitly deny permissions to key groups such as IU, SU, BA, SY, and WD using SID strings.
5.  The `sc.exe` command successfully applies the modified DACL to the targeted service, restricting access for the specified user groups.
6.  Attempts to manage or interact with the service through legitimate tools fail due to the altered permissions.
7.  The attacker maintains persistence by ensuring the service remains running and unmodifiable.
8.  The attacker achieves defense evasion by hindering security tools and administrators from detecting or terminating the service.

## Impact

Successful exploitation can lead to persistent malware execution as the modified service becomes difficult to manage or terminate. The number of victims can vary, depending on the scope of the initial compromise and the targeted systems. Sectors affected include any organization relying on Windows services. If the attack succeeds, critical services can be rendered unmanageable, causing operational disruption, or malicious services can remain hidden and persistent.

## Recommendation

*   Deploy the Sigma rule "Service DACL Modification via sc.exe" to your SIEM to detect suspicious `sc.exe` command executions modifying DACLs (see rules section).
*   Enable Sysmon process creation logging to capture the `sc.exe` commands with the `sdset` parameter.
*   Review existing service configurations and permissions to identify any unauthorized DACL modifications.
*   Monitor process execution for `sc.exe` commands containing `sdset` and access rights modifications targeting common user groups such as IU, SU, BA, SY, and WD, as specified in the rule query.
