---
title: Tampering with Windows Accessibility Binaries for Privilege Escalation
slug: 2026-10-accessibility-binary-tampering
description: Adversaries modify or replace Windows accessibility binaries such as sethc.exe and utilman.exe to establish persistence and bypass authentication mechanisms for unauthorized system access.
date: "2026-10-12T17:54:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*
tags:
  - persistence
  - privilege-escalation
  - windows
  - endpoint
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.008
    technique_name: Accessibility Features
    evidence: Adversaries can exploit these binaries to gain unauthorized access or execute commands without logging in.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546.008
    technique_name: Accessibility Features
    evidence: If confirmed malicious, this could allow attackers to bypass authentication mechanisms, potentially leading to unauthorized system access.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1546.008/T1546.008.yaml
rules:
  - title: Detect Modification of Windows Accessibility Binaries
    description: Detects unauthorized modifications or replacements of Windows accessibility binaries that are commonly exploited to bypass authentication.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.008
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM and audit existing file modification alerts.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic content
  mitigation_plan:
    - priority: short_term
      action: Restrict write access to C:\Windows\System32 to only authorized system service accounts.
      owner: IT Operations
      addresses: T1546.008
      evidence: Standard hardening practices for Windows system binaries
---

Adversaries frequently target Windows accessibility features - commonly known as the 'Sticky Keys' attack - to gain unauthorized, high-privilege access to a system. By replacing legitimate accessibility binaries located in C:\Windows\System32, such as sethc.exe, utilman.exe, osk.exe, Magnify.exe, Narrator.exe, DisplaySwitch.exe, and AtBroker.exe, attackers can trigger the execution of malicious code or a command shell at the Windows login screen. This technique effectively bypasses authentication, allowing an attacker to operate with SYSTEM-level privileges. This activity is a classic method for persistence and lateral movement, as it requires only file system write access to sensitive system directories. Defenders must monitor file modifications within the System32 directory to detect unauthorized changes to these binaries.

## Attack Chain

1. Attacker gains local administrative or SYSTEM privileges on the target Windows endpoint.
2. Attacker locates the targeted accessibility binary (e.g., C:\Windows\System32\sethc.exe).
3. Attacker takes ownership of the target binary and modifies permissions to allow replacement.
4. Attacker renames or moves the original binary (e.g., to sethc.exe.bak) to avoid detection or disruption.
5. Attacker replaces the original binary with a malicious executable or a copy of cmd.exe.
6. Attacker triggers the accessibility feature (e.g., pressing Shift five times) at the Windows logon screen.
7. The system executes the replaced binary, resulting in an unauthorized SYSTEM-level shell.
8. Attacker proceeds with further malicious activity or credential harvesting.

## Impact

Successful exploitation allows for full authentication bypass on the affected Windows system. This provides attackers with persistent, non-authenticated access to the host with SYSTEM-level privileges. This technique is frequently observed in post-compromise scenarios to maintain access across reboots and facilitate deeper environment compromise.

## Recommendation

* Monitor all write/modify operations targeting the C:\Windows\System32 directory, specifically for the accessibility binaries listed in this brief.
* Deploy the provided Sigma rule to alert on file creation or modification events matching the targeted binary names.
* Establish a baseline of known-good hashes for all Windows system binaries to identify unauthorized replacements.
* Configure Sysmon Event ID 11 (FileCreate) or equivalent EDR telemetry to log file write activity in the System32 path.
* Investigate any process spawning from the login screen context that is not expected to be a standard accessibility tool.
