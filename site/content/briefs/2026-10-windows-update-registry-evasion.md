---
title: Detection of Windows Update Registry Modification for Defense Evasion
slug: 2026-10-windows-update-registry-evasion
description: Adversaries, including the RedLine Stealer malware, modify Windows registry keys to disable automatic updates to facilitate evasion and prevent security patching.
date: "2026-10-12T18:12:08Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - RedLine Stealer
tags:
  - defense-evasion
  - registry-modification
  - windows
  - malware
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The following analytic detects a suspicious modification to the Windows registry that disables automatic updates.
    confidence_band: high
rules:
  - title: Detect Windows Update Auto-Update Disablement
    description: Detects registry modification to disable automatic Windows updates, a technique used by RedLine Stealer for defense evasion.
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
    - action: Deploy the Sigma detection rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection analytic.
  hunt_leads:
    - lead: Search historical registry modification logs for the identified path.
      technique_id: T1112
      data_needed:
        - Registry modification telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known TTP of RedLine Stealer.
  mitigation_plan:
    - priority: short_term
      action: Review Group Policy settings to ensure only approved systems have Windows Update disabled.
      owner: IT Operations
      addresses: Defense evasion via registry modification
      evidence: False positive guidance in source.
---

Adversaries and malware, such as the RedLine Stealer, employ registry modifications to impede system security by disabling automatic updates. By altering the Windows registry key located at "*\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\DoNotConnectToWindowsUpdateInternetLocations" and setting its value to "0x00000001", attackers force a host to disconnect from Windows Update services. This action serves a critical role in an adversary's post-compromise strategy by preventing the installation of security patches and hindering the reach of security-focused telemetry or OS-level defensive updates. Defenders should focus on monitoring registry write operations that target this specific configuration, as it is rarely modified in production environments for standard workstation usage.

## Attack Chain

1. Initial access is gained through methods such as credential harvesting or phishing.
2. The threat actor executes a malicious payload on the target system.
3. The malware checks for administrative privileges required to modify sensitive registry keys.
4. The malware writes to the Windows Registry at the path `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`.
5. The `DoNotConnectToWindowsUpdateInternetLocations` key is created or modified with the value `0x00000001`.
6. The system configuration is effectively altered to prevent connection to Microsoft update infrastructure.
7. The attacker proceeds with secondary objectives, such as exfiltrating stolen data or deploying additional payloads, free from the threat of OS-level security remediation.

## Impact

Successful modification of this registry key disables the target system's ability to receive security updates, leaving the environment vulnerable to unpatched exploits. This behavior is primarily observed in info-stealing malware campaigns that prioritize stealth and long-term persistence on infected hosts within a network.

## Recommendation

1. Deploy Sysmon to capture Registry Event ID 13 and focus on the `DoNotConnectToWindowsUpdateInternetLocations` path.
2. Implement the provided Sigma rule to alert on registry values matching `0x00000001` at the specified key.
3. Conduct an audit of your Group Policy Objects (GPOs) to identify if any authorized administrative policies are intentionally setting this value to ensure accurate alert tuning.
