---
brief_id: brief-2026-11-10-defender-wmi-evasion
event_id: brief-2026-11-10-defender-wmi-evasion
revision: 1
activity_at: "2026-11-10T10:51:22Z"
title: 'Windows Defender: WMI Autologger session tampering via Reg.exe'
slug: 2026-11-defender-wmi-evasion
description: Attackers utilize reg.exe to modify registry keys associated with Windows Defender ETW Autologger sessions, effectively disabling event logging for security monitoring.
date: "2026-11-10T10:51:22Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_reg_disable_defender_wmi_autologger.yml
  - https://research.splunk.com/endpoint/76406a0f-f5e0-4167-8e1f-337fdc0f1b0c/
  - https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
rules:
  - title: Detect Disabling of Windows Defender WMI Autologger
    description: Detects the use of reg.exe to set the Start value to 0 for the DefenderApiLogger or DefenderAuditLogger, which disables ETW logging for Defender.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
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
    - action: Deploy the provided Sigma rule to detect registry modifications targeting WMI Autologger sessions.
      owner: Detection Engineering
      due: 48h
      evidence: Source describes this as a powerful defense evasion technique.
  mitigation_plan:
    - priority: short_term
      action: Implement restricted access to registry paths under HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger.
      owner: IT Operations
      addresses: Defender ETW evasion
      evidence: Direct tampering with registry keys is the mechanism of attack.
---

This technique involves the modification of Windows Registry keys related to the Event Tracing for Windows (ETW) Autologger sessions specifically for 'DefenderApiLogger' and 'DefenderAuditLogger'. By setting the 'Start' registry value to '0' via the command line, attackers can silence the logging of critical Defender security events. This action impairs the visibility of security operations centers and endpoint detection and response (EDR) platforms that rely on ETW telemetry for threat detection.

## Impact

Successful execution of this technique prevents the generation of Defender API and Audit event logs, creating a blind spot in host-based monitoring. This allows attackers to perform further malicious actions without triggering detection mechanisms that depend on these specific event sources.

## Recommendation

- Deploy the provided Sigma rule to detect the use of 'reg.exe' for modifying Autologger start values.
- Baseline administrative registry modifications in your environment to distinguish legitimate system configuration from adversarial activity.
- Investigate any 'reg.exe' processes executing commands that target registry paths under 'Control\WMI\Autologger'.
