---
title: Potential Persistence via Mandatory User Profile Modification
slug: 2024-01-ntuser-man-persistence
description: Adversaries may abuse Windows mandatory profiles by dropping a malicious NTUSER.MAN file containing pre-populated persistence-related registry keys to establish persistence, which can evade traditional registry-based monitoring.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - mandatory-profile
  - file-modification
vendors:
  - Elastic
products:
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://deceptiq.com/blog/ntuser-man-registry-persistence
rules:
  - title: Potential Persistence via Mandatory User Profile Creation
    description: Detects the creation of NTUSER.MAN file by non-system processes which may indicate malicious persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Potential Persistence via Mandatory User Profile Modification
    description: Detects the modification of NTUSER.MAN file by non-system processes which may indicate malicious persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers may leverage Windows mandatory profiles to achieve persistence by crafting or modifying an `NTUSER.MAN` file containing malicious registry entries. Windows loads registry settings directly from this file when a user logs in, causing embedded persistence mechanisms, such as Run keys or logon scripts, to activate. This technique allows adversaries to establish persistence without directly modifying the live registry, potentially evading detection by traditional registry-based monitoring tools. This technique may be used for stealthy persistence on systems where mandatory profiles are in use.

## Attack Chain

1. The adversary gains initial access to the system, possibly through exploiting a vulnerability or using stolen credentials.
2. The attacker locates a user profile directory on the system, typically found under `C:\\Users\\`.
3. The attacker creates or modifies an `NTUSER.MAN` file within the user's profile directory. This file contains registry settings that will be loaded when the user logs in.
4. The adversary embeds malicious registry keys within the `NTUSER.MAN` file, such as entries in the `Run` or `RunOnce` keys, or configurations for logon scripts.
5. The user logs off and then logs back onto the system.
6. Upon logon, Windows loads the registry settings from the `NTUSER.MAN` file.
7. The malicious registry keys are executed, enabling the attacker to establish persistence or perform other malicious activities.
8. The adversary maintains persistence on the system, enabling them to execute commands, install malware, or steal data.

## Impact

Successful exploitation allows attackers to establish a persistent presence on the compromised system. This can lead to unauthorized access to sensitive data, further compromise of the network, and potential data exfiltration. The use of mandatory profiles for persistence can make detection more challenging as the malicious activity is triggered during user logon.

## Recommendation

*   Deploy the Sigma rule "Potential Persistence via Mandatory User Profile Creation" to detect the creation of NTUSER.MAN files by non-SYSTEM processes (see below).
*   Deploy the Sigma rule "Potential Persistence via Mandatory User Profile Modification" to detect modification of NTUSER.MAN files by non-SYSTEM processes (see below).
*   Monitor file creation and modification events related to `NTUSER.MAN` in user profile directories to identify suspicious activity.
*   Review endpoint detection coverage to ensure offline registry hive and profile-based persistence techniques are monitored.
*   Investigate any file creation or modification of NTUSER.MAN files by reviewing process.name, process.executable, and parent process relationships.
