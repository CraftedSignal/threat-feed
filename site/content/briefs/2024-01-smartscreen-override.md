---
title: Windows Defender SmartScreen Prompt Override via Registry Modification
slug: 2024-01-smartscreen-override
description: Attackers modify the Windows registry to disable SmartScreen prompt overrides, potentially allowing users to bypass security warnings and execute harmful content, leading to system compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - smartscreen
vendors:
  - Microsoft
  - Splunk
products:
  - Edge
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Detect SmartScreen Prompt Override
    description: Detects modifications to the Windows registry that override the Windows Defender SmartScreen prompt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
  - title: Detect SmartScreen Prompt Override - Sysmon Event 13
    description: Detects modifications to the Windows registry that override the Windows Defender SmartScreen prompt using Sysmon Event ID 13.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This threat brief focuses on a technique used to impair Windows Defender SmartScreen protection by modifying specific registry settings. The attack involves altering the "PreventSmartScreenPromptOverride" registry value to allow users to bypass SmartScreen warnings. This manipulation effectively disables a key security control, making systems more vulnerable to malware and phishing attacks. While specific threat actors are not attributed in the source, the technique is a common tactic used by various threat actors to weaken defenses before or during an attack. This technique has been observed as recently as January 2024. This matters to defenders because SmartScreen is a critical defense against drive-by downloads and malicious websites. Disabling it greatly increases the attack surface.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the system through unspecified means (e.g., compromised credentials or exploitation of a vulnerability).
2.  **Privilege Escalation (if needed):** The attacker may need to escalate privileges to modify the registry.
3.  **Registry Modification:** The attacker modifies the registry value at `HKLM\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride` or `HKCU\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride`.
4.  **Setting Value to 0:** The attacker sets the `PreventSmartScreenPromptOverride` value to `0x00000000`, effectively disabling the prompt override prevention.
5.  **SmartScreen Weakening:** With the registry change in place, SmartScreen prompt overrides are allowed, reducing the effectiveness of the security feature.
6.  **User Interaction:** The attacker relies on user interaction (e.g., clicking a malicious link or opening a malicious file) to execute harmful content.
7.  **Malware Execution:** The user bypasses the SmartScreen warning, leading to the execution of malware or malicious code.
8.  **System Compromise:** The executed malware compromises the system, potentially leading to data theft, further exploitation, or other malicious activities.

## Impact

The impact of a successful SmartScreen override can be significant. Systems become more vulnerable to malware and phishing attacks, potentially leading to widespread infections, data breaches, and financial losses. While the exact number of victims is unknown, any system where this registry modification occurs is at increased risk. This technique is particularly effective in organizations with less security awareness or where users may be more prone to bypassing security warnings.

## Recommendation

*   Enable Sysmon EventID 13 logging to monitor registry modifications as indicated by the `data_source` field.
*   Deploy the Sigma rule `Detect SmartScreen Prompt Override` to your SIEM and tune for your environment.
*   Monitor changes to the `PreventSmartScreenPromptOverride` registry setting specifically using the `registry_path` field in the provided search query.
*   Investigate any alerts triggered by the Sigma rule to determine if the registry modification is malicious based on the `description`.
