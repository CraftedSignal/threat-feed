---
title: Tampering with Windows Security Center Notifications
slug: 2026-10-windows-security-center-tampering
description: Adversaries, including the Azorult malware group, modify registry keys to disable Windows Security Center notifications as a defense evasion tactic to suppress system alerts.
date: "2026-10-12T18:11:22Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Azorult
tags:
  - defense-evasion
  - registry-modification
  - windows
  - azorult
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
    evidence: The analytic detects modifications to the Windows registry aimed at disabling Windows Security Center notifications.
    confidence_band: high
rules:
  - title: Detect Registry Modification to Disable Windows Security Center Notifications
    description: Detects modifications to the Windows registry aimed at disabling Windows Security Center notifications by setting UseActionCenterExperience to 0
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
    - action: Deploy the Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for registry monitoring
  hunt_leads:
    - lead: Search for historical instances of UseActionCenterExperience set to 0
      technique_id: T1112
      data_needed:
        - Endpoint Registry logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Registry key modification is a known TTP for Azorult
  mitigation_plan:
    - priority: short_term
      action: Review Group Policy settings for Windows Security Center and ensure consistent configuration across the estate
      owner: IT Operations
      addresses: T1112
      evidence: Preventing unauthorized registry changes through GPO prevents this TTP
---

Adversaries and malware variants, notably Azorult, employ registry modification techniques to disable Windows Security Center notifications. By targeting the 'UseActionCenterExperience' registry key and setting its value to 0, attackers suppress critical security warnings and update notifications that would otherwise alert the user to malicious activity or missing security patches. This defense evasion tactic increases the likelihood of long-term persistence, as attackers can operate with a reduced risk of being interrupted by system-level security prompts. Defenders should monitor for unauthorized modifications to the Windows ImmersiveShell registry hive, which is frequently targeted to weaken host-based defenses.

## Attack Chain

1. Initial malware execution on the host system (e.g., Azorult dropper).
2. The process identifies the need to suppress user notifications to maintain stealth.
3. The malware checks for administrative privileges required to modify HKLM registry hives.
4. The malware executes a registry write operation to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\UseActionCenterExperience`.
5. The registry value is explicitly set to `0x00000000` to disable the Action Center experience.
6. The system suppresses subsequent security notifications and warnings.
7. The attacker proceeds with post-exploitation objectives, such as exfiltrating data or deploying additional payloads.

## Impact

Successful suppression of security notifications allows malicious actors to maintain persistence and execute follow-on operations undetected. While specific victim counts are not provided, this technique is a recognized component of various malware campaigns, including Azorult, which primarily targets credentials and sensitive system information.

## Recommendation

1. Deploy the Sigma rule provided in this brief to detect unauthorized modifications to the identified registry path.
2. Configure Sysmon Event ID 13 to log registry modifications and ensure that HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell is included in your monitoring scope.
3. Correlate alerts from this registry modification with other endpoint process creation events (Event ID 1) to identify the parent process responsible for the registry change.
4. Establish a baseline of authorized configuration management tools (e.g., SCCM, GPO) that legitimately modify this registry key to minimize false positives from administrative activity.
