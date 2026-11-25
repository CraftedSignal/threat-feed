---
brief_id: brief-2026-11-25-visualuiaverifynative
event_id: brief-2026-11-25-visualuiaverifynative
revision: 1
activity_at: "2026-11-25T16:28:19Z"
title: 'Microsoft Windows SDK: Potential Application Control Bypass via VisualUiaVerifyNative.exe'
slug: 2026-11-visualuiaverifynative
description: VisualUiaVerifyNative.exe, a component of the Windows SDK, is identified by Microsoft as a binary capable of bypassing Windows Defender Application Control (WDAC) policies and should be included in block lists.
date: "2026-11-25T16:28:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic defined based on community-sourced LOLBAS intelligence; environment validation required to identify scope of legitimate usage.
tags:
  - lolbin
  - awl-bypass
  - application-control
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: VisualUiaVerifyNative.exe is a Windows SDK that can be used for AWL bypass and is listed in Microsoft's recommended block rules.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_lolbin_visualuiaverifynative.yml
rules:
  - title: Execution of VisualUiaVerifyNative.exe
    description: Detects the execution of the VisualUiaVerifyNative.exe binary, which is known for potential use in Application Whitelisting (AWL) bypasses.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Add VisualUiaVerifyNative.exe to enterprise WDAC block lists.
      owner: IT Operations
      due: 72h
      evidence: Listed in Microsoft's recommended block rules.
  hunt_leads:
    - lead: Search for historical execution patterns of VisualUiaVerifyNative.exe in endpoint telemetry to baseline legitimate usage.
      technique_id: T1218
      data_needed:
        - Process creation events (Event ID 1)
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Presence on production systems is generally unnecessary for standard users.
  mitigation_plan:
    - priority: short_term
      action: Implement application control policy to block the execution of VisualUiaVerifyNative.exe.
      owner: IT Operations
      addresses: Application control bypass capability of VisualUiaVerifyNative.exe
      evidence: Listed in Microsoft's recommended block rules.
---

## Overview

VisualUiaVerifyNative.exe is a legitimate Microsoft Windows SDK binary that has been identified as a security risk due to its potential use in Application Whitelisting (AWL) bypasses. Microsoft lists this binary in its recommended WDAC block rules to prevent its abuse as a living-off-the-land binary (LOLBin). There is currently no evidence of specific widespread exploitation campaigns, but its presence on production systems is generally unnecessary for standard user operation and poses an elevated risk to application control integrity.

## Recommendation

1. Review environments for the presence of VisualUiaVerifyNative.exe. 
2. Integrate the binary into existing WDAC or AppLocker block policies as recommended by Microsoft.
3. Deploy the provided detection rule to monitor for execution of this process in environments where it is not required for software development or UI testing tasks.
