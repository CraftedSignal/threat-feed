---
title: Registry Modification to Disable Windows Defender Notifications
slug: 2026-10-windows-defender-notification-disable
description: Adversaries, including RedLine Stealer, modify registry keys to disable Windows Defender notifications, allowing malicious activity to proceed without alerting the user or security teams.
date: "2026-10-12T18:11:13Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - RedLine Stealer
cpes:
  - cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*
tags:
  - defense-evasion
  - registry
  - windows-defender
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
    evidence: This activity is significant as it indicates an attempt to evade detection by disabling security alerts, a technique used by adversaries and malware like RedLine Stealer.
    confidence_band: high
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1112/T1112.yaml#L796
rules:
  - title: Detect Registry Modification to Disable Windows Defender Notifications
    description: Detects an attempt to disable Windows Defender notifications by modifying the registry, a technique used by RedLine Stealer to evade security alerts.
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
    - action: Deploy the Sigma rule to monitor for DisableNotifications registry modifications.
      owner: Detection Engineering
      due: 24h
      evidence: Registry modification identified as a detection evasion TTP.
  hunt_leads:
    - lead: Search for instances of DisableNotifications set to 0x00000001 across the fleet.
      technique_id: T1112
      data_needed:
        - Endpoint registry telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This registry key is a known artifact of RedLine Stealer evasion.
  mitigation_plan:
    - priority: short_term
      action: Enforce policy settings via Group Policy Objects (GPO) to prevent end-user or unauthorized binary modification of security registry keys.
      owner: IT Operations
      addresses: T1112
      evidence: Hardening registry paths prevents tampering.
---

Adversaries and malware, such as the RedLine Stealer infostealer, frequently employ techniques to evade detection on compromised Windows endpoints. One such method involves the manipulation of the Windows Registry to silence security alerts by disabling Windows Defender notifications. By setting the 'DisableNotifications' registry value to '1' within the Windows Defender Security Center policies, attackers effectively suppress warnings that would otherwise notify users of malicious activity or the presence of unauthorized software. This evasion technique is critical for threat actors attempting to maintain persistence and conduct data exfiltration or credential theft while minimizing the likelihood of immediate user intervention. Defenders should monitor registry modifications for this specific key as a high-fidelity indicator of post-exploitation activity.

## Attack Chain

1. Initial access is established through phishing or exploit kits, resulting in the execution of the RedLine Stealer binary.
2. The malware gains elevated privileges or executes within a user session with sufficient permissions to modify system policies.
3. The adversary identifies the target registry path: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications.
4. Using native Windows utilities or built-in API calls, the malware creates or modifies the 'DisableNotifications' value.
5. The registry value is set to '0x00000001' to force the suppression of security alerts.
6. The adversary proceeds with additional malicious objectives, such as browser data theft, credential dumping, or command-and-control communication.
7. Because security notifications are disabled, the user does not receive alerts regarding the initial compromise or subsequent suspicious process execution.
8. The final objective is achieved, such as the exfiltration of sensitive information, with a reduced risk of early detection.

## Impact

Successful suppression of Windows Defender notifications significantly increases the risk of successful data exfiltration and long-term endpoint compromise. By silencing security alerts, adversaries can operate with greater stealth, extending their dwell time and decreasing the probability that a user will report suspicious system behavior or unauthorized modifications.

## Recommendation

- Deploy the provided Sigma rule to detect modifications to the specified Windows Defender registry path.
- Monitor Sysmon Event ID 13 (RegistryValueset) for changes to the 'DisableNotifications' key.
- Audit administrative access to system registry policies to prevent unauthorized policy modification.
- Investigate any 'DisableNotifications' registry change occurring in conjunction with unknown or unsigned binaries.
