---
title: Windows Defender Web Content Evaluation Disabled via Registry Modification
slug: 2024-01-disable-web-evaluation
description: An attacker modifies the Windows registry to disable Windows Defender web content evaluation, potentially allowing malicious web content to bypass security checks and compromise the system.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - registry-modification
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Detect Registry Modification to Disable Web Content Evaluation (Process Creation)
    description: Detects processes modifying the registry to disable Windows Defender web content evaluation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Registry Modification to Disable Web Content Evaluation (Registry Event)
    description: Detects registry events indicating the disabling of Windows Defender web content evaluation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers can disable Windows Defender's web content evaluation feature by modifying the `EnableWebContentEvaluation` registry entry. This defense evasion technique, often employed post-compromise, allows malicious web content to bypass security checks, increasing the risk of system exploitation. Disabling this feature is not a common practice in standard Windows system administration and its presence is a strong indicator of malicious activity. This activity matters for defenders, as it weakens the overall security posture of the system, making it more susceptible to web-based attacks.

## Attack Chain

1.  Initial access to the system is achieved through an existing compromise or vulnerability exploitation.
2.  The attacker gains elevated privileges to modify the registry.
3.  The attacker uses a process (e.g., `reg.exe`, `powershell.exe`) to modify the registry key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation`.
4.  The `EnableWebContentEvaluation` value is set to `0x00000000`, disabling the web content evaluation feature.
5.  The system is now more susceptible to web-based attacks, as malicious scripts and unsafe web elements can bypass security checks.
6.  The attacker leverages the weakened security posture to execute malicious code or exfiltrate sensitive data.
7.  The attacker maintains persistence by ensuring the registry modification remains in place.

## Impact

Disabling Windows Defender's web content evaluation feature exposes systems to a higher risk of web-based attacks. Successful exploitation could lead to malware infection, data theft, or complete system compromise. The impact is significant, as it weakens a key security control, potentially affecting numerous users and systems within an organization.

## Recommendation

*   Enable Sysmon Event ID 13 to monitor registry modifications and activate the provided Sigma rules (process_creation and registry_set).
*   Deploy the provided Sigma rules to your SIEM to detect attempts to disable web content evaluation via registry modifications and tune for your environment.
*   Investigate any alerts triggered by the Sigma rules, focusing on the processes responsible for the registry changes (process_creation, registry_set).
*   Consider using the provided filter macro to tune the search to reduce false positives based on your environment.
