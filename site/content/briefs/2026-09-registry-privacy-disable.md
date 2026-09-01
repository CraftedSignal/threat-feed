---
title: Registry Modification to Disable Privacy Settings Experience
slug: 2026-09-registry-privacy-disable
description: Adversaries, including those observed deploying LockBit Black, modify registry keys to disable the Windows Privacy Settings Experience as part of a defense impairment strategy.
date: "2026-09-01T12:09:38Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - LockBit Black
tags:
  - defense-impairment
  - registry-tampering
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_disable_privacy_settings_experience.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1562.001/T1562.001.md
rules:
  - title: Detect Registry Modification to Disable Privacy Settings Experience
    description: Detects registry modifications that set DisablePrivacyExperience to 0, which disables the Windows Privacy Settings Experience.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
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
    - action: Deploy registry monitoring rules for OOBE policy paths.
      owner: Detection Engineering
      due: 48h
      evidence: Sigma rule provided in brief.
  hunt_leads:
    - lead: Search for existing registry keys set to disable privacy experience.
      technique_id: T1685
      data_needed:
        - Registry auditing logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source describes technique as a defense impairment activity.
---

Adversaries often seek to impair system security and management features to facilitate stealthier operations. One documented technique involves the modification of the Windows Registry to disable the Privacy Settings Experience. By setting the 'DisablePrivacyExperience' value within the 'SOFTWARE\Policies\Microsoft\Windows\OOBE\' registry key to 0, attackers can prevent the Windows Out-of-Box Experience (OOBE) from prompting users regarding privacy configurations. This behavior has been observed in the context of LockBit Black ransomware deployments, where the threat actor aims to minimize system interruptions and user awareness during the compromise phase. This technique falls under the broader category of defense impairment, as it limits the visibility of security-related system settings.

## Attack Chain

1. Initial access is established on the Windows host via spearphishing or exploited vulnerability.
2. The actor gains elevated privileges required to modify HKLM or HKCU registry hives.
3. The attacker locates the registry path 'SOFTWARE\Policies\Microsoft\Windows\OOBE'.
4. The attacker executes a command, such as 'reg add' or a PowerShell Set-ItemProperty, to create or modify the 'DisablePrivacyExperience' key.
5. The registry value is set to '0x00000000' to suppress the privacy interface.
6. Persistence or further payload execution continues, with the OOBE privacy prompts now permanently disabled for the user session.
7. Final objectives, such as data exfiltration or ransomware deployment, are carried out with reduced likelihood of user interaction.

## Impact

Successful execution of this technique results in the suppression of OS-level privacy configuration prompts. While the primary damage is the impairment of system security awareness and the potential for configuration hardening against user intent, it serves as a reliable indicator of malicious activity or unauthorized administrative configuration changes within enterprise environments.

## Recommendation

Deploy the provided Sigma rule to monitor for registry modifications targeting OOBE policy keys. Investigate any instances where 'DisablePrivacyExperience' is set to 0, particularly if the parent process is not an authorized configuration management tool (e.g., SCCM, Group Policy client). Prioritize alerts originating from endpoints that have recently exhibited other indicators of lateral movement or credential access.
