---
title: RegPwnBOF Registry Symlink Race Condition Exploit
slug: 2024-01-regpwnbof
description: RegPwnBOF exploits a registry symlink race condition in the Windows Accessibility ATConfig mechanism, enabling a normal user to write arbitrary values to protected HKLM registry keys for persistence and privilege escalation.
date: "2026-03-19T05:23:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - registry
  - symlink
  - race-condition
  - accessibility
  - privilege-escalation
  - persistence
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rxrt45/regpwnbof_bof_of_regpwn_exploits_a_registry/
  - https://github.com/Flangvik/RegPwnBOF
rules:
  - title: Detect Suspicious Registry Symlink Creation
    description: Detects the creation of registry symlinks potentially used for privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect Modification of Accessibility Settings via ATConfig
    description: Detects modification of registry keys associated with accessibility features which may indicate RegPwnBOF activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

RegPwnBOF is an exploit leveraging a registry symlink race condition within the Windows Accessibility ATConfig mechanism. This vulnerability allows an unprivileged user to manipulate protected areas of the registry, specifically HKLM, which are typically reserved for administrators or system processes. By exploiting this race condition, an attacker can write arbitrary values to these protected keys. The initial report surfaced around March 2026, highlighting the potential for unauthorized persistence and privilege escalation. This circumvents standard Windows security controls, posing a significant risk to system integrity and confidentiality. The exploit's accessibility to non-administrator users makes it particularly dangerous in environments where least-privilege principles are not strictly enforced.

## Attack Chain

1.  An unprivileged user initiates the ATConfig mechanism within the Windows Accessibility features.
2.  The exploit creates a registry symlink pointing to a protected HKLM key.
3.  A race condition is triggered during the ATConfig process, allowing the exploit to bypass security checks.
4.  The attacker leverages this race condition to overwrite the target HKLM registry key with arbitrary data.
5.  The modified registry key is used to establish persistence, for example, by creating a Run key.
6.  Upon system restart or user login, the malicious payload associated with the modified Run key is executed.
7.  The attacker gains elevated privileges by executing code within the context of a privileged process.

## Impact

Successful exploitation of RegPwnBOF allows an attacker to gain persistent access to a compromised system and escalate their privileges to administrator level. This can lead to complete system compromise, data theft, and the installation of malware. The impact is magnified by the fact that this exploit can be triggered by a normal user, bypassing traditional access controls. The number of potential victims is considerable, as the vulnerability exists within the Windows Accessibility features, which are enabled by default on many systems.

## Recommendation

*   Monitor registry modifications targeting HKLM keys, especially those related to Accessibility features, using a process_creation log source and the provided Sigma rules.
*   Implement strict access controls and least-privilege principles to limit the ability of unprivileged users to interact with system-level configurations.
*   Investigate any unusual registry symlink creation events using file_event logs, particularly those involving the ATConfig mechanism, to identify potential RegPwnBOF exploitation attempts.
