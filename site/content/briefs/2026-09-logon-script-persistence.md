---
title: Detection of Potential Persistence via Logon Script Registry Modification
slug: 2026-09-logon-script-persistence
description: Detection of adversaries modifying the UserInitMprLogonScript registry value to establish persistence via logon scripts.
date: "2026-09-03T12:41:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - windows
  - registry
  - defense-evasion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1037
    technique_name: Logon Script
    evidence: Detects the addition of a new LogonScript to the registry value UserInitMprLogonScript for potential persistence
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_registry_logon_script.yml
  - https://cocomelonc.github.io/persistence/2022/12/09/malware-pers-20.html
rules:
  - title: Potential Persistence Via Logon Scripts - CommandLine
    description: Detects the addition of a new LogonScript to the registry value UserInitMprLogonScript for potential persistence
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1037.001
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
    - action: Deploy the Sigma rule to detect suspicious modifications of UserInitMprLogonScript
      owner: Detection Engineering
      due: 48h
      evidence: Source provides Sigma rule logic
  hunt_leads:
    - lead: Search for existing UserInitMprLogonScript entries in the registry that reference files in non-standard paths
      technique_id: T1037.001
      data_needed:
        - Registry auditing logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This registry key is a known persistence vector
---

Adversaries often attempt to achieve persistence on Windows systems by modifying registry keys that execute code automatically during user logon. One such mechanism involves the "UserInitMprLogonScript" registry value. By adding a malicious executable or script path to this value, an attacker ensures their code runs with the privileges of the user who logs on to the system. While this technique is traditionally associated with registry modifications, command-line tools like "reg.exe" are frequently used to perform these modifications stealthily or during post-exploitation activities. Defenders should monitor for command-line arguments that attempt to write to or modify this specific registry path, as such actions are rarely required for routine administrative tasks and often signal unauthorized persistence efforts.

## Attack Chain

1. Attacker gains initial access to the target host (e.g., via spearphishing or exploit).
2. Attacker executes a shell or drops a payload to the disk.
3. Attacker identifies the need for persistent access to survive system reboots.
4. Attacker uses "reg.exe" or similar tools to interact with the Windows Registry.
5. Attacker executes "reg add" to set or append a value to "HKCU\Environment\UserInitMprLogonScript" pointing to a malicious binary or script.
6. Victim user logs into the system.
7. Windows automatically executes the path specified in "UserInitMprLogonScript" during the login process.
8. Attacker code executes with the user's privileges, establishing persistent access.

## Impact

Successful exploitation results in unauthorized persistence, allowing attackers to maintain access across user sessions and system reboots. This technique effectively grants the attacker the ability to execute arbitrary code with the privileges of any user who logs into the compromised machine, increasing the risk of data exfiltration and credential theft.

## Recommendation

- Deploy the Sigma rule below to detect instances of "UserInitMprLogonScript" being referenced in command-line arguments.
- Monitor logs for unauthorized use of "reg.exe" or "reg add" involving environment-related registry keys.
- Audit existing "UserInitMprLogonScript" registry values across the fleet for unexpected file paths.
