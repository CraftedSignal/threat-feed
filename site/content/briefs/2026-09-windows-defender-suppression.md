---
title: Suppression of Windows Security Center Notifications
slug: 2026-09-windows-defender-suppression
description: Adversaries modify Windows Registry keys to disable Windows Security Center notifications, facilitating defense impairment and persistence.
date: "2026-09-01T12:13:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-impairment
  - windows
  - security-hardening
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The modification of registry keys to change security settings is documented under T1112.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The target registry path is used to impair Windows Defender defensive notifications.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_suppress_defender_notifications.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1112/T1112.md
rules:
  - title: Detect Windows Security Center Notification Suppression
    description: Detects the modification of the Notification_Suppress registry value to 1, which disables Windows security center notifications.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - persistence
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
    - action: Deploy Sigma rule for Registry set events to monitor notification suppression.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 0c93308a-3f1b-40a9-b649-57ea1a1c1d63
  hunt_leads:
    - lead: Search historical registry logs for the key path to identify prior unauthorized changes.
      technique_id: T1112
      data_needed:
        - Registry set events (Event ID 13)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Registry path identified in detection logic.
  mitigation_plan:
    - priority: medium
      action: Enforce Windows Defender settings via GPO to overwrite manual registry modifications.
      owner: IT Operations
      addresses: T1112
      evidence: Standard security hardening practice.
---

Adversaries frequently employ defense impairment techniques to reduce the visibility of malicious activity or security warnings. One such method involves modifying the Windows Registry to disable notifications from the Windows Security Center, including those related to Microsoft Defender. By setting the 'Notification_Suppress' value within the 'UX Configuration' key of the Windows Defender policies, an attacker can prevent the operating system from alerting the user or the security operations center to potential threats detected by Windows Defender. This modification is often part of a broader post-exploitation effort to maintain persistence or conduct additional malicious activities without interference from security alerts. This technique is well-documented in the Atomic Red Team framework under T1112 (Modify Registry) and serves as a critical indicator for identifying attempts to subvert endpoint security controls.

## Impact

Successful suppression of security notifications blinds end-users to critical security events, potentially allowing malware to execute, persist, or exfiltrate data undetected by the standard Windows Defender warning system. While this does not necessarily disable the Defender scanning engine itself, it significantly degrades the security posture of the endpoint by masking active alerts.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for unauthorized modifications to the Windows Defender registry configuration.

* Enable registry object auditing via Group Policy for the 'SOFTWARE\Policies\Microsoft\Windows Defender' path.
* Deploy the Sigma rule below to detect 'Notification_Suppress' set to '1'.
* Investigate any detected registry changes for unauthorized process or user account context.
