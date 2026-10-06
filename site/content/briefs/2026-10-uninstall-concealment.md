---
title: Potential Uninstall Entry Concealment via HideUL or Registry Modification
slug: 2026-10-uninstall-concealment
description: Adversaries may hide malicious software such as remote-access tools from the Windows Programs and Features list by executing the HideUL utility or modifying the SystemComponent registry value.
date: "2026-10-06T11:58:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - registry
  - persistence
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Adversaries may use either method to conceal remote-access, security, or other software.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: Identifies execution of the Hide From Uninstall List utility or a registry change that marks an installed application as a system component.
    confidence_band: high
references:
  - https://www.huntress.com/blog/daisy-chaining-rogue-rmm-tools
  - https://www.microsoft.com/en-us/security/blog/2026/09/29/phishing-abuses-rmm-tools-persistent-access
  - https://www.sordum.org/11081/hide-from-uninstall-list-v1-1/
rules:
  - title: Detect Potential Uninstall Entry Concealment
    description: Detects the execution of HideUL utilities or registry modifications setting SystemComponent to 1 to hide applications from the uninstall list.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1564
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule for HideUL and SystemComponent registry modifications.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for existing SystemComponent=1 entries in the registry that do not match authorized deployment software.
      technique_id: T1112
      priority: medium
      confidence: medium
      disposition: hunt_now
---

Adversaries frequently employ techniques to conceal installed software from the Windows 'Programs and Features' control panel to maintain persistence and evade detection. This concealment is typically achieved through two primary methods: the execution of specialized utilities like 'Hide From Uninstall List' (HideUL) or direct manipulation of the Windows Registry. By setting the 'SystemComponent' value to '1' within the registry subkey of an application under 'Software\Microsoft\Windows\CurrentVersion\Uninstall', attackers can force the operating system to treat the application as a core system component, thereby removing it from the user-facing uninstallation list. This technique is commonly observed in the context of persistent remote-access tool deployment, security tool neutralization, and broader defense evasion strategies. Defenders must distinguish these unauthorized modifications from legitimate system administration, packaging, or kiosk hardening workflows that may also utilize the 'SystemComponent' flag.

## Attack Chain

1. Attacker gains initial access to a Windows system, often via phishing or exploited RMM tools.
2. Attacker deploys a malicious payload (e.g., a remote-access trojan or persistent beacon).
3. Attacker executes the payload on the target system.
4. Attacker identifies the registry uninstall subkey for the installed malicious binary.
5. Attacker executes 'HideUL.exe' or modifies the registry to set 'SystemComponent' to '1' for the target application entry.
6. The application is hidden from the 'Programs and Features' UI to prevent user or administrator discovery.
7. Attacker proceeds with the final objective, such as credential theft, lateral movement, or data exfiltration.

## Impact

Successful concealment of malicious tools reduces the likelihood of detection by end-users and non-specialized administrators, increasing the dwell time of attackers within the environment. This technique is often associated with the deployment of ransomware and rogue remote-management software, which can lead to complete compromise of the affected host and potential lateral movement into the broader network.

## Recommendation

Prioritize the identification of unauthorized 'SystemComponent' registry modifications.
- Deploy the provided Sigma rule to detect both the execution of HideUL binaries and suspicious modifications to registry uninstall keys.
- Establish a baseline of legitimate software management and deployment tools that utilize the 'SystemComponent' flag to reduce false positives.
- Review process parent-child relationships for registry modification events originating from non-administrative or unexpected binaries.
