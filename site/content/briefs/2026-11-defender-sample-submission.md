---
brief_id: brief-2026-11-10-defender-sample-submission
event_id: brief-2026-11-10-defender-sample-submission
revision: 1
activity_at: "2026-11-10T02:42:49Z"
title: 'Windows Defender: Automatic sample submission feature disabled'
slug: 2026-11-defender-sample-submission
description: Detection of the disabling of the "Automatic Sample Submission" feature of Windows Defender.
date: "2026-11-10T02:42:49Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - defense-impairment
  - T1685
  - windows-defender
references:
  - https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus?view=o365-worldwide
  - https://web.archive.org/web/20221222070510/https://bidouillesecurity.com/disable-windows-defender-in-powershell/#DisableAntiSpyware
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/windefend/win_defender_config_change_sample_submission_consent.yml
rules:
  - title: Detect Windows Defender Automatic Sample Submission Disabled
    description: Detects disabling of the "Automatic Sample Submission" feature of Windows Defender.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
    data_sources:
      - windows
      - windefend
rules_count: 1
---

The "Automatic Sample Submission" feature of Windows Defender can be disabled, which modifies the antimalware platform configuration. This event is logged via Event ID 5007.

## Recommendation
- Monitor Windows event logs for Event ID 5007.
- Investigate occurrences of this configuration change, as they may result from administrator activity.
