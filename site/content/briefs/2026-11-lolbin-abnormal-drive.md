---
brief_id: brief-2026-11-10-lolbin-abnormal-drive
event_id: brief-2026-11-10-lolbin-abnormal-drive
revision: 1
activity_at: "2026-11-10T03:04:50Z"
title: Living-off-the-land Binary Execution from Non-System Drives
slug: 2026-11-lolbin-abnormal-drive
description: This detection focuses on the execution of common Windows system binaries (LOLBins) originating from non-standard drive locations, a technique frequently used in ransomware and loader deployments to bypass directory-based execution restrictions.
date: "2026-11-10T03:04:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Detection logic verified against standard Sysmon Event ID 1 schema
tags:
  - windows
  - living-off-the-land
  - detection-engineering
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_lolbin_exec_from_non_c_drive.yml
rules:
  - title: Detect LOLBIN Execution From Abnormal Drive
    description: Detects common LOLBins executing from drives other than C:, often indicative of execution from mounted ISOs or removable media
    platform: sigma
    severity: medium
    tactics:
      - stealth
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify processes spawned from non-standard drive letters
      data_needed:
        - CurrentDirectory
        - Image
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source notes that LOLBINs executing from abnormal drives are a TTP observed in ransomware and loader campaigns.
---

Attackers often leverage mounted ISO files, removable media, or temporary drive mappings to execute malicious code using legitimate system tools. This behavior is documented in multiple incident reports involving malware loaders and ransomware groups that rely on bypassing standard C: drive execution monitoring.

## Impact
Execution of signed system binaries from non-standard drives can facilitate lateral movement, payload execution, and persistence while evading traditional path-based allowlists.

## Recommendation
- Deploy the provided Sigma rule to monitor for process creation events originating from drives other than C:.
- Baseline common administrative tasks in the environment to reduce false positives on multi-drive servers.
- Review process creation logs for LOLBins (e.g., rundll32, regsvr32, mshta) where the CurrentDirectory field does not begin with 'C:\'.
