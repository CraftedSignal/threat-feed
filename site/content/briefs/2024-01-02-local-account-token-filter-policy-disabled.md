---
title: Local Account TokenFilter Policy Modification for Defense Evasion and Lateral Movement
slug: 2024-01-02-local-account-token-filter-policy-disabled
description: Adversaries may modify the LocalAccountTokenFilterPolicy registry key to bypass User Account Control (UAC) and gain elevated privileges remotely by granting high-integrity tokens to remote connections from local administrators, facilitating lateral movement and defense evasion.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - lateral-movement
  - persistence
  - registry-modification
vendors:
  - Elastic
  - Microsoft
  - SentinelOne
  - Crowdstrike
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Crowdstrike FDR
affected_os:
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
  - title: Local Account TokenFilter Policy Enabled
    description: Detects when the LocalAccountTokenFilterPolicy registry key is enabled, which can be used to bypass UAC when performing lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1112
      - T1548.002
      - T1550.002
    data_sources:
      - registry_set
      - windows
  - title: Local Account TokenFilter Policy Modified by Uncommon Process
    description: Detects modification of LocalAccountTokenFilterPolicy by processes not typically associated with system configuration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - lateral_movement
    techniques:
      - T1112
      - T1548.002
      - T1550.002
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The LocalAccountTokenFilterPolicy is a Windows registry setting that, when enabled (set to 1), allows remote connections from local members of the Administrators group to be granted full high-integrity tokens during negotiation. This bypasses User Account Control (UAC) restrictions, allowing for elevated privileges remotely. Attackers may modify this registry setting to facilitate lateral movement within a network. This rule detects modifications to this specific registry setting, alerting on potential unauthorized changes that could lead to defense evasion and privilege escalation. The modification of this policy has been observed being leveraged in conjunction with pass-the-hash attacks.

## Attack Chain

1.  The attacker gains initial access to a system through an exploit, such as phishing or exploiting a vulnerability.
2.  The attacker obtains local administrator credentials on the compromised system.
3.  The attacker modifies the LocalAccountTokenFilterPolicy registry key to a value of 1. This is done to allow remote connections from local administrator accounts to receive high-integrity tokens. The registry key is typically located at `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy`.
4.  The attacker leverages a "pass the hash" attack (T1550.002) using the compromised local administrator credentials.
5.  The attacker attempts to move laterally to other systems within the network using the "pass the hash" technique and the modified LocalAccountTokenFilterPolicy.
6.  Due to the LocalAccountTokenFilterPolicy being enabled, the remote connection from the local administrator account receives a full high-integrity token.
7.  The attacker bypasses UAC on the remote system, gaining elevated privileges.
8.  The attacker performs malicious activities on the remote system, such as data exfiltration or deploying ransomware.

## Impact

Successful modification of the LocalAccountTokenFilterPolicy allows attackers to bypass User Account Control (UAC) and gain elevated privileges on remote systems, potentially leading to unauthorized access to sensitive data, lateral movement across the network, and the deployment of ransomware. The overall impact can include data breaches, financial loss, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Local Account TokenFilter Policy Enabled` to your SIEM and tune for your environment to detect unauthorized modifications to the LocalAccountTokenFilterPolicy registry key.
*   Enable Sysmon registry event logging to capture modifications to the registry, which is required for the `Local Account TokenFilter Policy Enabled` Sigma rule.
*   Review the processes excluded in the rule query and ensure they are legitimate and necessary to prevent false positives.
*   Monitor registry events for changes to the `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` path, specifically looking for changes to the value data.
