---
title: Detection of Registry Modifications Disabling Password Changes
slug: 2026-10-windows-disable-password-change
description: Attackers, particularly ransomware actors, modify the Windows registry to disable the Change Password feature, preventing users from regaining control of their accounts and impeding incident response.
date: "2026-10-12T18:03:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ransomware
  - defense-evasion
  - registry-tampering
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The following analytic detects a suspicious registry modification that disables the Change Password feature on a Windows host.
    confidence_band: high
rules:
  - title: Detect Windows Disable Change Password Registry Modification
    description: Detects modifications to the 'DisableChangePassword' registry key, which disables the ability for users to change their Windows passwords.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 24h
      evidence: Registry modification logic identified.
  mitigation_plan:
    - priority: medium_term
      action: Review Group Policy Objects (GPO) to ensure only authorized changes to the 'DisableChangePassword' registry key are permitted.
      owner: IT Operations
      addresses: T1112
      evidence: Registry manipulation is a common persistence and evasion technique.
---

Adversaries often target the Windows registry to disable the user's ability to change their passwords, a technique categorized under Defense Evasion. By modifying the registry key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableChangePassword' and setting its value to '0x00000001', attackers can effectively lock out users from modifying security credentials. This activity is commonly associated with ransomware operations, where maintaining persistent control over a compromised host is critical for the attacker's objectives. By inhibiting password changes, attackers frustrate user-led remediation efforts and complicate administrative incident response, allowing more time for lateral movement or data exfiltration. Defenders should monitor registry modifications targeting this path to identify unauthorized attempts to weaken host security controls.

## Attack Chain

1. Initial access is established on the victim system via phishing or exploitation.
2. The attacker gains administrative or SYSTEM level privileges required to modify sensitive registry keys.
3. The adversary identifies the 'DisableChangePassword' registry value within the Windows Policies hive.
4. The attacker executes a command (e.g., reg.exe or PowerShell) to set the 'DisableChangePassword' value to '1'.
5. The change is persisted in the registry, immediately disabling the Change Password function in the Windows Security (Ctrl+Alt+Del) menu.
6. The attacker prevents the user from successfully resetting credentials, maintaining unauthorized control over the compromised session.
7. Final objective is achieved, such as the encryption of user files or the extraction of sensitive data from the host.

## Impact

This technique impacts organizations by neutralizing a primary mechanism for users to protect their accounts after detecting a security incident. Successful exploitation results in persistent control for the attacker, enabling prolonged access to the system. While the total number of victims is not publicly quantified for this specific registry modification, it is a known tactic utilized in various ransomware campaigns to increase the operational friction for security teams attempting to re-secure endpoints.

## Recommendation

* Deploy the Sigma rule provided in this brief to detect unauthorized registry modifications to the 'DisableChangePassword' key.
* Enable Sysmon Event ID 13 (RegistryEvent) logging to capture registry set operations across all workstations and servers.
* Create a whitelist in your SIEM to filter out legitimate administrative tools or software deployment scripts that may legitimately set this policy for security hardening.
* Monitor for suspicious process execution (e.g., reg.exe) occurring in conjunction with the registry write event to identify the process responsible for the modification.
