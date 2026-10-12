---
title: Windows Registry Modification to Disable Logoff Functionality
slug: 2026-10-windows-logoff-registry
description: Adversaries, specifically ransomware operators, modify Windows Registry keys to disable the logoff button, hindering incident response and forcing session persistence.
date: "2026-10-12T18:04:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - ransomware
  - registry
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
    evidence: The following analytic detects a suspicious registry modification that disables the logoff feature on a Windows host.
    confidence_band: high
references:
  - https://www.hybrid-analysis.com/sample/e2d4018fd3bd541c153af98ef7c25b2bf4a66bc3bfb89e437cde89fd08a9dd7b/5b1f4d947ca3e10f22714774
  - https://malwiki.org/index.php?title=DigiPop.xp
  - https://www.trendmicro.com/vinfo/be/threat-encyclopedia/search/js_noclose.e/2
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1112/T1112.yaml#L244
rules:
  - title: Detect Registry Modification to Disable Logoff
    description: Detects registry modifications to 'NoLogOff' or 'StartMenuLogOff' in the explorer policies key, a technique often used by ransomware to persist in user sessions.
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
    - action: Deploy registry monitoring for 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' modifications.
      owner: Detection Engineering
      due: 48h
      evidence: Source document indicates this is a technique for ransomware persistence.
  hunt_leads:
    - lead: Search for existing 'NoLogOff' entries in the registry across the estate.
      technique_id: T1112
      data_needed:
        - Registry auditing logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This registry key is commonly abused to lock users into sessions.
  mitigation_plan:
    - priority: medium_term
      action: Standardize endpoint configurations via GPO to overwrite malicious registry modifications.
      owner: IT Operations
      addresses: T1112
      evidence: Manual registry changes can be remediated through authoritative GPO settings.
---

Adversaries, particularly those deploying ransomware, may modify Windows Registry keys to intentionally disable the logoff functionality on a compromised system. By targeting the 'NoLogOff' or 'StartMenuLogOff' registry values within the 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' path, an attacker can prevent a user from ending their session. This technique is often used to complicate incident response, as it forces users to remain logged in, thereby preserving the attacker's persistence on the system and potentially preventing administrative remediation efforts from terminating malicious sessions. This behavior has been observed in various ransomware campaigns aiming to make the host unusable for the victim while maintaining unauthorized control over the environment.

## Attack Chain

1. The attacker gains initial access to the Windows host through phishing, exploit, or credential theft.
2. The attacker executes a malicious binary or script with sufficient privileges to modify the Windows Registry.
3. The attacker locates the target registry hive, typically 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\'.
4. The attacker adds or modifies the 'NoLogOff' or 'StartMenuLogOff' registry value name.
5. The attacker sets the registry value data to '0x00000001' to effectively disable the logoff feature.
6. The system policy is updated, immediately reflecting the change in the Windows shell and preventing the user from performing a normal logoff.
7. The attacker proceeds with additional stages, such as data exfiltration or ransomware encryption, while the active user session remains locked into the compromised environment.

## Impact

Successful implementation of this modification prevents users from logging off, which complicates incident response and containment procedures for security teams. This tactic is primarily used to prolong the window of opportunity for ransomware operators to finalize their objectives before detection or system reboot occurs.

## Recommendation

- Deploy the Sigma rule below to detect unauthorized modifications to explorer-related registry keys.
- Establish a monitoring baseline for registry changes occurring in 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\' to identify non-administrative activity.
- Investigate the originating process responsible for the registry change, as this often points to the primary malware or staging script used in the incident.
