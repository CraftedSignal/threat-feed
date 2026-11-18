---
brief_id: brief-2026-11-18-system-dll-sideloading-hunt
event_id: brief-2026-11-18-system-dll-sideloading-hunt
revision: 1
activity_at: "2026-11-18T13:50:20Z"
title: Detection of DLL Sideloading via System DLL Misplacement
slug: 2026-11-system-dll-sideloading-hunt
description: This brief outlines a method to detect the placement of system-named DLLs in non-standard file system locations, a technique often used to facilitate DLL sideloading.
date: "2026-11-18T13:50:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
qa_status:
  verdict: pass
tags:
  - defense-evasion
  - stealth
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    subtechnique_id: T1036.005
    subtechnique_name: Match Legitimate Name or Location
    evidence: Detects the creation of a file with the .dll extension that has the name of a System DLL in uncommon or unsuspected locations.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_creation_system_dll_files.yml
rules:
  - title: Detect Files With System DLL Name In Unsuspected Locations
    description: Detects the creation of a file with the .dll extension that has the name of a known system DLL in uncommon locations outside of standard system directories.
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
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Baseline local file system activity to identify common third-party applications that include their own copies of system DLLs.
      owner: Detection Engineering
      due: 7d
      evidence: Third party software might bundle specific versions of system DLLs.
    - action: Deploy the Sigma detection rule to monitor for file creation events matching system DLL names.
      owner: Detection Engineering
      due: 3d
      evidence: Sigma rule provided in source
---

## Overview

Security researchers have documented a technique where attackers place files with names matching legitimate system DLLs (such as secur32.dll or tdh.dll) into directories outside of standard Windows system paths like System32 or SysWOW64. This placement is a common precursor to DLL sideloading, where an application is tricked into loading the malicious DLL instead of the genuine system version. Due to the potential for benign third-party software to bundle local copies of these DLLs, baseline activity must be established before production alerting.

## Recommendation

- Deploy the provided Sigma rule to monitor for file creation events involving system DLLs in non-standard directories.
- Establish a baseline of legitimate third-party software that bundles system DLLs to reduce noise.
- Use the detection to identify anomalous file write operations that may precede DLL sideloading attempts.
