---
title: Suspicious System Process Names in Unusual File Locations
slug: 2026-07-system-file-locations
description: This brief detects an attacker's attempt to evade detection and maintain persistence by creating executable files with names identical to legitimate Windows system processes in non-standard directories, a tactic associated with stealth and defense evasion.
date: "2026-07-28T08:22:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - defense-evasion
  - persistence
  - windows
  - file-event
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Detects the creation of an executable with a system process name in folders other than the system ones (System32, SysWOW64, etc.).
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_system_file.yml
rules:
  - title: Files With System Process Name In Unsuspected Locations
    description: Detects the creation of an executable with a system process name in folders other than the expected system ones (System32, SysWOW64, etc.), a common defense evasion technique.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1036.005
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This threat brief focuses on the technique where adversaries create executable files that mimic the names of legitimate Windows system processes, but place them in directories outside of their expected system paths (e.g., System32, SysWOW64). This method is a common tactic for defense evasion and persistence, as it helps attackers blend malicious executables with benign system activity, making them harder to distinguish by security tools and human analysts. While the source does not detail a specific threat actor or campaign, this technique has been observed in various APT attacks, such as by the SideWinder APT, to conceal their malicious operations. The detection capability targets the creation of files like `explorer.exe`, `svchost.exe`, `lsass.exe`, or `powershell.exe` in locations where they should not legitimately reside, indicating a high likelihood of malicious intent.

## Impact

Successful deployment of executables masquerading as system processes can lead to various detrimental outcomes for an organization. Adversaries can achieve stealthy persistence, execute malicious code with elevated privileges, or evade detection from security solutions that might be configured to trust standard system process names. The impact can range from data exfiltration and intellectual property theft to system compromise, ransomware deployment, or complete network control, depending on the attacker's ultimate objectives. The inherent challenge in distinguishing these malicious files from legitimate system components significantly increases the attacker's dwell time and ability to conduct further nefarious activities unnoticed.

## Recommendation

* Deploy the Sigma rule "Files With System Process Name In Unsuspected Locations" to your SIEM and tune for your environment to detect file creations matching system process names in unusual directories.
* Ensure Sysmon `file_event` logging is enabled to provide the necessary telemetry for the provided Sigma rule.
* Perform an initial baseline of your environment to identify legitimate third-party software or uncommon system configurations that might trigger false positives for the "Files With System Process Name In Unsuspected Locations" rule.
