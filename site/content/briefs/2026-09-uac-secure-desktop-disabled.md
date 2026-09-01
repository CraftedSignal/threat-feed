---
title: Modification of UAC Secure Desktop Prompt Registry Setting
slug: 2026-09-uac-secure-desktop-disabled
description: An adversary or unauthorized user modifies the Windows registry to disable the UAC secure desktop prompt, reducing security by allowing UAC elevation requests to appear on the user's desktop where they may be intercepted by malicious processes.
date: "2026-09-01T12:14:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: The PromptOnSecureDesktop setting specifically determines whether UAC prompts are displayed on the secure desktop.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_disable_secure_desktop_prompt.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/7e11e9b79583545f208a6dc3fa062f2ed443d999/atomics/T1548.002/T1548.002.md
rules:
  - title: Detect UAC Secure Desktop Prompt Disabled via Registry
    description: Detects when the PromptOnSecureDesktop registry value is set to 0, which disables the UAC secure desktop prompt.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1548.002
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
    - action: Deploy Sigma detection rule to production SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides concrete registry path and value for detection
  hunt_leads:
    - lead: Search for historical changes to PromptOnSecureDesktop in registry logs
      technique_id: T1548.002
      data_needed:
        - Registry modification event logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Modification of this key is a standard indicator of UAC bypass or security weakening
  mitigation_plan:
    - priority: immediate
      action: Ensure Group Policy settings enforce PromptOnSecureDesktop = 1 across all workstations
      owner: IT Operations
      addresses: T1548.002
      evidence: Secure desktop is a core Windows security control
---

This threat involves the modification of the Windows registry key 'PromptOnSecureDesktop' under 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'. The secure desktop is an isolated environment designed to prevent malicious software from intercepting or tampering with User Account Control (UAC) elevation prompts. By changing this registry value to 0, an attacker forces UAC prompts to appear on the user's primary desktop. This configuration change is often associated with privilege escalation efforts, as it potentially exposes the elevation interface to UI automation, screen scraping, or click-jacking techniques that would otherwise be blocked by the isolated secure desktop environment. Defenders should monitor registry modifications targeting this path to detect attempts to weaken Windows system security controls.

## Impact

Disabling the UAC secure desktop prompt lowers the defensive posture of the host operating system. If successful, this creates an environment where malicious software can interact with or manipulate elevation requests, potentially facilitating unauthorized privilege escalation or bypassing security warnings. This technique is frequently used as a precursor to more sophisticated attacks that require persistent or elevated access.

## Recommendation

Deploy the provided Sigma rule to monitor for registry modifications to the 'PromptOnSecureDesktop' value. Establish an alert baseline for any account, especially non-administrative accounts, that initiates changes to 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'. Use the telemetry captured to identify the parent process responsible for the registry change, as this is likely the primary indicator of an ongoing compromise or unauthorized configuration change.
