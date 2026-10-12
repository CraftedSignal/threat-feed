---
title: Detection of Registry Modification to Disable Windows Notification Center
slug: 2026-10-windows-notification-center-disable
description: Malware families, including Remote Access Trojans (RATs), modify Windows registry keys to disable the Notification Center, effectively suppressing system alerts to hide malicious activity.
date: "2026-10-12T18:04:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows-registry
  - persistence
  - monitoring
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The analytic detects the modification of the Windows registry to disable the Notification Center on a host machine.
    confidence_band: high
references:
  - https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1112/T1112.yaml
rules:
  - title: Detect Windows Notification Center Disabled via Registry
    description: Detects the modification of the registry value DisableNotificationCenter to 0x00000001, which is a technique used by RATs to evade detection by suppressing system alerts.
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
    - action: Deploy the registry monitoring rule to detect attempts to disable the Notification Center.
      owner: Detection Engineering
      due: 48h
      evidence: This activity is significant because disabling the Notification Center can be a tactic used by RAT malware.
  hunt_leads:
    - lead: Search historical registry modification logs for instances of 'DisableNotificationCenter' being set to '1'.
      technique_id: T1112
      data_needed:
        - Registry change logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The detection is specifically looking for changes to the 'DisableNotificationCenter' registry value set to '0x00000001'.
  mitigation_plan:
    - priority: medium
      action: Enforce standard Windows hardening via Group Policy to prevent unauthorized registry modifications.
      owner: IT Operations
      addresses: T1112
      evidence: Registry modification can be a tactic used by RAT malware.
---

This threat brief focuses on an endpoint defense evasion technique where the Windows Notification Center is programmatically disabled via registry modification. This activity is frequently observed in the behavior of various Remote Access Trojans (RATs), such as Remcos RAT, as a method to conceal system alerts, security notifications, and user-facing feedback regarding the execution of malicious tasks. By setting the "DisableNotificationCenter" registry value to "0x00000001", an attacker can maintain stealth during lateral movement or data exfiltration, ensuring the victim remains unaware of automated system interactions. Detection engineering teams should monitor registry modifications for this specific key to identify potential compromises that attempt to bypass standard Windows security visibility features.

## Attack Chain

1. An initial access vector (e.g., phishing or exploit) delivers the primary RAT payload to the host system.
2. The payload executes with sufficient privileges to modify the Windows registry.
3. The malware performs an anti-analysis check to determine if security products or the Notification Center are active.
4. The process accesses the registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer` or `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`.
5. The attacker sets the `DisableNotificationCenter` value to `0x00000001` to suppress OS-level notifications.
6. The system state is modified, causing subsequent security warnings or application alerts to be silently discarded by the OS.
7. The attacker proceeds with secondary objectives, such as keylogging, file exfiltration, or further persistence, without triggering visible alerts for the logged-in user.

## Impact

The suppression of the Notification Center allows attackers to operate with reduced friction, as common security warnings from Windows Defender or other installed software may be hidden from the end user. This stealth increases the likelihood that a compromised machine remains infected for an extended period, facilitating unauthorized access to sensitive data and potential expansion into the wider network environment.

## Recommendation

* Deploy the provided Sigma rule to monitor for registry modifications targeting the `DisableNotificationCenter` key.
* Establish a baseline for administrative changes within your environment to tune out legitimate IT configuration scripts that may modify this registry value.
* Ingest Sysmon Event ID 13 (RegistryEvent) logs to ensure visibility into registry value modifications across all endpoints.
* Investigate the `process_guid` associated with any triggers of the rule to identify the originating malicious process and perform containment.
