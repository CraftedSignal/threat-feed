---
title: Windows Registry Modification to Suppress Defender Notifications
slug: 2026-10-windows-defender-notification-suppression
description: Adversaries, including those using Azorult malware, modify the 'Notification_Suppress' registry key to disable Windows Defender alerts and facilitate stealthy persistence.
date: "2026-10-12T18:13:41Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Azorult
tags:
  - defense-evasion
  - registry
  - windows
  - azorult
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Adversaries, including those deploying Azorult malware, use this technique to bypass Windows Defender and disable critical notifications.
    confidence_band: high
rules:
  - title: Detect Windows Defender Notification Suppression
    description: Detects modifications to the Windows registry to suppress Windows Defender notifications, often used by malware like Azorult for defense evasion.
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
    - action: Deploy the Sigma detection rule to monitor for registry-based suppression of security notifications.
      owner: Detection Engineering
      due: 48h
      evidence: Registry modification identified as a known defense evasion technique.
  hunt_leads:
    - lead: Search for instances of 'Notification_Suppress' being set to 0x00000001 in registry logs.
      technique_id: T1112
      data_needed:
        - Sysmon Event ID 13
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Registry modification behavior matches observed malicious activity.
  mitigation_plan:
    - priority: medium_term
      action: Enforce Windows Defender settings via Group Policy or MDM to prevent unauthorized registry modification.
      owner: IT Operations
      addresses: T1112
      evidence: Centralized policy management prevents local registry tempering.
---

Adversaries frequently employ techniques to neutralize security monitoring on infected endpoints. A notable method involves modifying the Windows registry key located at 'HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\Notification_Suppress'. By setting this value to '0x00000001', attackers successfully suppress Windows Defender notifications, preventing users from receiving critical security alerts regarding malicious activity.

This technique is commonly observed in the deployment of Azorult malware, where attackers aim to minimize the visible footprint of their malicious operations. By disabling these notifications, the threat actor can maintain persistence and execute follow-on malicious activities without immediate detection by the user. Defenders should monitor registry modifications targeting this specific path as a high-fidelity indicator of potential defense evasion.

## Attack Chain

1. The attacker gains initial access to the target endpoint, typically through phishing or exploitation of vulnerable software.
2. The attacker executes a malicious payload, such as the Azorult malware, to establish a foothold on the system.
3. The malware checks for the presence of Windows Defender and its associated security configurations.
4. The attacker performs a registry write operation to 'HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\Notification_Suppress'.
5. The 'Notification_Suppress' registry value is set to '0x00000001' to disable security alerts.
6. The threat actor proceeds to deploy additional malicious modules or exfiltrate sensitive data from the system.
7. The attacker maintains long-term persistence, confident that the suppressed notifications will mask ongoing malicious behavior from the user.

## Impact

Successful suppression of Windows Defender notifications significantly reduces the visibility of malicious activity on compromised hosts. This technique allows threat actors to evade detection, conduct data exfiltration, and establish persistence, increasing the risk of full system compromise within the targeted environment.

## Recommendation

* Monitor registry modifications targeting the 'Notification_Suppress' registry value via Sysmon Event ID 13.
* Deploy the provided Sigma rule to identify unauthorized attempts to disable Windows Defender notifications.
* Establish an allowlist for legitimate administrative tools that may perform these registry modifications for maintenance purposes.
* Investigate endpoints where this registry modification occurs to determine the responsible process and confirm if it originates from an authorized management tool.
