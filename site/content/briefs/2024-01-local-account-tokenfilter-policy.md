---
title: Local Account TokenFilter Policy Modification
slug: 2024-01-local-account-tokenfilter-policy
description: An adversary modifies the LocalAccountTokenFilterPolicy registry key to weaken security controls and enable privilege escalation, allowing them to bypass User Account Control (UAC) and gain elevated privileges remotely.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - lateral-movement
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://www.stigviewer.com/stig/windows_server_2008_r2_member_server/2014-04-02/finding/V-36439
  - https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167
  - https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf
rules:
  - title: Detect Local Account TokenFilter Policy Modification
    description: Detects modifications to the LocalAccountTokenFilterPolicy registry key, indicating a potential attempt to bypass UAC and gain elevated privileges.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1550.002
      - T1562
    data_sources:
      - registry_set
      - windows
  - title: Detect Local Account TokenFilter Policy Creation
    description: Detects creation of the LocalAccountTokenFilterPolicy registry key, which is not present by default, indicating a potential attempt to bypass UAC and gain elevated privileges.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1550.002
      - T1562
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers modify the `LocalAccountTokenFilterPolicy` registry setting to weaken system security. This policy, when set to '1', grants remote connections from local administrators full high-integrity tokens, effectively bypassing User Account Control (UAC). This allows attackers to remotely execute commands with elevated privileges. This technique can be used for lateral movement and defense evasion. The modification of this registry key indicates a potential attempt to facilitate lateral movement or evade defenses within a Windows environment.

## Attack Chain

1.  The attacker gains initial access to the target system, potentially through compromised credentials or exploitation of a vulnerability.
2.  The attacker uses an administrative account or exploits a privilege escalation vulnerability to obtain necessary rights to modify the registry.
3.  The attacker modifies the `LocalAccountTokenFilterPolicy` registry value located at `HKLM\*\LocalAccountTokenFilterPolicy` to `1` or `0x00000001`.
4.  The system's security posture is weakened due to the policy change, enabling remote connections from local administrators to use full high-integrity tokens.
5.  The attacker initiates a remote connection to the system, utilizing a local administrator account.
6.  The attacker is granted full high-integrity tokens during authentication, bypassing UAC restrictions.
7.  The attacker executes malicious commands or deploys malware with elevated privileges remotely.
8.  The attacker achieves lateral movement and gains control over additional systems within the network or impairs defenses.

## Impact

Successful modification of the `LocalAccountTokenFilterPolicy` allows attackers to bypass UAC and gain elevated privileges remotely. This can lead to lateral movement, data exfiltration, or system compromise. The impact is significant, as it weakens the system's security posture and allows attackers to operate with elevated privileges, potentially affecting all systems where the modified policy is in effect.

## Recommendation

*   Enable Sysmon registry event logging to monitor changes to the `LocalAccountTokenFilterPolicy` registry key (rule: "Detect Local Account TokenFilter Policy Modification").
*   Deploy the Sigma rule "Detect Local Account TokenFilter Policy Modification" to your SIEM and tune it for your environment.
*   Investigate any detected modifications of the `LocalAccountTokenFilterPolicy` registry key, identifying the user and process responsible for the change, as outlined in the investigation guide.
*   Regularly review and audit registry settings related to security policies to ensure they align with organizational security standards.
