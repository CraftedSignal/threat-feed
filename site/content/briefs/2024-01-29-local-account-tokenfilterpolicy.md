---
title: Local Account TokenFilter Policy Modification for Defense Evasion
slug: 2024-01-29-local-account-tokenfilterpolicy
description: Modification of the LocalAccountTokenFilterPolicy registry key to enable high-integrity tokens for local administrator accounts is detected, potentially allowing attackers to bypass User Account Control (UAC) and facilitate lateral movement.
date: "2024-01-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - lateral-movement
  - registry-modification
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://www.stigviewer.com/stig/windows_server_2008_r2_member_server/2014-04-02/finding/V-36439
  - https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167
  - https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf
rules:
  - title: Local Account TokenFilter Policy Modification
    description: Detects modification of the LocalAccountTokenFilterPolicy registry value.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1112
      - T1550.002
    data_sources:
      - registry_set
      - windows
  - title: Local Account TokenFilter Policy Modification via PowerShell
    description: Detects modification of the LocalAccountTokenFilterPolicy registry value via PowerShell.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1059.001
      - T1112
      - T1550.002
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The LocalAccountTokenFilterPolicy is a Windows registry setting that, when configured, permits remote connections from local administrators to utilize full high-integrity tokens. This behavior deviates from the default Windows security model and can be abused by attackers to bypass User Account Control (UAC) and elevate privileges remotely. The modification of this setting is often employed as a defense evasion and lateral movement technique. This rule detects changes to the `LocalAccountTokenFilterPolicy` registry value, specifically when it is set to `1`, which enables the aforementioned behavior. Monitoring for this modification helps defenders identify potential attempts to weaken system security and facilitate unauthorized access. This activity is associated with threat actors attempting to use pass-the-hash techniques.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to a system, potentially through compromised credentials or exploitation of a vulnerability.
2.  **Privilege Escalation:** The attacker escalates privileges on the local system using exploits or misconfigurations.
3.  **Registry Modification:** The attacker modifies the `LocalAccountTokenFilterPolicy` registry value to `1`, enabling high-integrity tokens for local administrators. This is achieved by writing to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`.
4.  **Credential Access:** The attacker leverages tools like Mimikatz to extract credentials from the system's memory.
5.  **Pass the Hash:** With the `LocalAccountTokenFilterPolicy` enabled, the attacker uses "pass-the-hash" techniques to authenticate to other systems on the network using the stolen credentials.
6.  **Lateral Movement:** The attacker moves laterally to other systems on the network, gaining access to sensitive data and resources.
7.  **Defense Evasion:** By using legitimate administrator accounts with high-integrity tokens, the attacker bypasses security controls and avoids detection.

## Impact

Successful modification of the `LocalAccountTokenFilterPolicy` can lead to widespread compromise of systems within a network. Attackers can move laterally with elevated privileges, gaining access to sensitive data, installing malware, or disrupting business operations. The number of affected systems depends on the scope of the attacker's lateral movement capabilities. Sectors heavily reliant on Windows-based networks are particularly vulnerable.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect unauthorized modifications to the `LocalAccountTokenFilterPolicy` registry key.
*   Enable Sysmon process creation logging to improve visibility into the processes modifying the registry, allowing for better attribution and context (reference: Sigma rule `Local Account TokenFilter Policy Modification`).
*   Review and whitelist legitimate uses of tools that may modify the `LocalAccountTokenFilterPolicy` to reduce false positives, referencing the existing exclusions in the provided EQL query.
*   Implement strict password policies and multi-factor authentication to mitigate the risk of credential theft and "pass-the-hash" attacks (reference: MITRE ATT&CK T1550.002).
*   Monitor for remote connections initiated by local administrator accounts, which may indicate exploitation of the `LocalAccountTokenFilterPolicy` vulnerability.
