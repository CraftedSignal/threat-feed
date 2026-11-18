---
brief_id: brief-2026-11-18-uac-bypass-silentcleanup
event_id: brief-2026-11-18-uac-bypass-silentcleanup
revision: 1
activity_at: "2026-11-18T13:51:09Z"
title: Bypass UAC Using SilentCleanup Task
slug: 2026-11-uac-bypass-silentcleanup
description: Attackers can bypass User Account Control (UAC) by modifying the "windir" environment variable to abuse the auto-elevated "SilentCleanup" task.
date: "2026-11-18T13:51:09Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.privilege-escalation
  - attack.t1548.002
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.002
    technique_name: Bypass User Account Control
    evidence: Attackers often abuse this variable in order to trigger a UAC bypass via the "SilentCleanup" task.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1548.002/T1548.002.md#atomic-test-9---bypass-uac-using-silentcleanup-task
  - https://www.reddit.com/r/hacking/comments/ajtrws/bypassing_highest_uac_level_windows_810/
  - https://www.fortinet.com/blog/threat-research/enter-the-darkgate-new-cryptocurrency-mining-and-ransomware-campaign
rules:
  - title: Bypass UAC Using SilentCleanup Task
    description: Detects the setting of the environment variable "windir" to a non-default value, which can be abused to trigger a UAC bypass via the SilentCleanup task.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1548.002
    data_sources:
      - registry_set
      - windows
rules_count: 1
---

## Overview
The "SilentCleanup" task, located at %windir%\system32\cleanmgr.exe, is a Windows auto-elevated task. Attackers may abuse this task to elevate a file with administrator privileges without prompting UAC by setting the "windir" environment variable to a non-default value.

## Impact
Successful exploitation allows an attacker to elevate a file with administrator privileges, effectively bypassing UAC protections.

## Recommendation
Monitor for registry modifications where the "windir" environment variable is set to a value other than the default "%SystemRoot%" setting.
