---
title: Windows Registry Modification to Disable Toast Notifications
slug: 2026-10-windows-toast-notifications
description: Adversaries, including operators of the Azorult malware, modify the Windows Registry to disable toast notifications, preventing users from receiving critical system security updates.
date: "2026-10-12T18:11:01Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Azorult
tags:
  - windows
  - registry
  - defense-evasion
  - malware
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
    evidence: The following analytic detects modifications to the Windows registry that disable toast notifications.
    confidence_band: high
references:
  - https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1112/T1112.yaml#L563
rules:
  - title: Detect Registry Modification to Disable Toast Notifications
    description: Detects modification of the Windows Registry ToastEnabled value to 0x00000000, which disables user notifications.
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
    - action: Deploy the Sigma rule provided in this brief.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit path and value for registry-based evasion.
  hunt_leads:
    - lead: Search endpoint registry logs for any historical changes to the PushNotifications\ToastEnabled key.
      technique_id: T1112
      data_needed:
        - Registry modification logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Malicious modification of this key is a known tactic for Azorult.
---

Adversaries, most notably operators of the Azorult infostealer malware, have been observed modifying the Windows Registry to disable toast notifications. By setting the value of the registry key "SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\ToastEnabled" to "0x00000000", attackers prevent the operating system from displaying critical system and security alerts. This technique is primarily utilized for defense evasion, as it effectively hides security warnings, updates, or error messages from the end user. By suppressing these notifications, the malware can operate with reduced scrutiny, increasing its chances of maintaining persistence and conducting data exfiltration without detection. This behavior is relevant for defenders as a indicator of compromise (IOC) for malware activity on compromised endpoints.

## Attack Chain

1. Initial infection via a payload delivery mechanism such as a phishing email or drive-by download.
2. Execution of the malware binary on the target system.
3. Escalation of privileges (if necessary) to gain the required access to modify the HKLM or HKCU registry hives.
4. Execution of a registry modification command (e.g., via reg.exe or API calls) targeting the PushNotifications key.
5. The specific registry value "ToastEnabled" is updated to "0x00000000".
6. Windows stops displaying desktop toast notifications for system and application events.
7. Malware proceeds with its primary objective, such as credential harvesting or further payload deployment.

## Impact

The impact of this activity is the suppression of critical security and system notifications. Victims who are targeted by Azorult or similar malware variants may fail to notice security alerts regarding system integrity, expired credentials, or software vulnerabilities. This leads to prolonged attacker dwell time, increased risk of system-wide data compromise, and reduced visibility for both the end user and security operations center (SOC) personnel.

## Recommendation

* Deploy the provided Sigma rule to detect unauthorized modifications to the registry key responsible for toast notifications.
* Use Sysmon Event ID 13 to monitor "RegistryEvent (Value Set)" operations specifically targeting the "ToastEnabled" path.
* Investigate endpoints where this modification occurs, especially if the process performing the change is not a legitimate system update or management tool.
* Implement endpoint detection and response (EDR) logic to alert on any process modifying registry values under "PushNotifications" in the absence of a known, approved administrative account or tool.
