---
brief_id: brief-2026-11-10-hh-susp-child
event_id: brief-2026-11-10-hh-susp-child
revision: 1
activity_at: "2026-11-10T05:36:36Z"
title: Microsoft HTML Help (hh.exe) Suspicious Child Process Execution
slug: 2026-11-hh-susp-child
description: Attackers utilize the legitimate Microsoft HTML Help utility (hh.exe) to execute malicious child processes as a living-off-the-land technique for initial access and payload delivery.
date: "2026-11-10T05:36:36Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - living-off-the-land
  - execution
  - windows
  - process-creation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    subtechnique_id: T1218.001
    subtechnique_name: Compiled HTML File
    evidence: Adversaries leverage this utility to execute arbitrary commands or scripts, effectively bypassing security controls.
    confidence_band: high
references:
  - https://www.levelblue.com/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan
  - https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
  - https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt37
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_hh_html_help_susp_child_process.yml
rules:
  - title: HTML Help HH.EXE Suspicious Child Process
    description: Detects a suspicious child process spawned by the Microsoft HTML Help utility (hh.exe), which is a common pattern in living-off-the-land attacks.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1218.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for child processes of hh.exe
      owner: Detection Engineering
      due: 48h
      evidence: Source provides common child process artifacts for hh.exe
  mitigation_plan:
    - priority: short_term
      action: Enable process creation logging with command line arguments for monitoring
      owner: IT Operations
      addresses: T1218.001
      evidence: Requirement for detection
---

Microsoft HTML Help (hh.exe) is a legitimate Windows utility used to open Compiled HTML Help (.chm) files. Adversaries leverage this utility to execute arbitrary commands or scripts, effectively bypassing security controls that might otherwise block direct execution of malicious binaries or scripts. By crafting malicious CHM files that contain embedded script triggers, attackers can spawn suspicious child processes to conduct further stages of an attack.

## Attack Chain
1. Delivery of a malicious .chm file to the target system via email or web download.
2. Execution of the .chm file, which automatically invokes 'hh.exe'.
3. Processing of the Compiled HTML Help content by 'hh.exe'.
4. Triggering of malicious embedded script (e.g., JScript or VBScript) within the .chm file context.
5. Spawning of a child process (e.g., cmd.exe, powershell.exe) by 'hh.exe' to execute secondary payloads or scripts.
6. Execution of further malicious operations by the spawned child process.

## Recommendation
- Deploy the provided Sigma rule to detect suspicious child processes spawned by hh.exe.
- Baseline legitimate usage of .chm files in the environment to reduce false positives.
- Implement application control or execution policies that restrict or alert on the execution of common scripting engines (e.g., powershell.exe, cscript.exe) when spawned by hh.exe.
