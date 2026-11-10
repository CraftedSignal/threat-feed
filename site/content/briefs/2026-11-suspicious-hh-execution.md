---
brief_id: brief-2026-11-10-suspicious-hh-execution
event_id: brief-2026-11-10-suspicious-hh-execution
revision: 1
activity_at: "2026-11-10T02:50:45Z"
title: Suspicious Microsoft HTML Help (HH.exe) Execution
slug: 2026-11-suspicious-hh-execution
description: Adversaries leverage the Microsoft HTML Help executable (hh.exe) to execute malicious CHM files, a technique historically associated with delivering payloads such as banking trojans and backdoors.
date: "2026-11-10T02:50:45Z"
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
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218.001
    technique_name: Compiled HTML File
    evidence: Adversaries may abuse hh.exe to execute malicious CHM files.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566.001
    technique_name: Spearphishing Attachment
    evidence: The technique is often used to deliver payloads via malicious attachments.
    confidence_band: high
references:
  - https://www.levelblue.com/blogs/spiderlabs-blog/chm-badness-delivers-a-banking-trojan
  - https://www.ptsecurity.com/ww-en/analytics/pt-esc-threat-intelligence/higaisa-or-winnti-apt-41-backdoors-old-and-new/
  - https://www.zscaler.com/blogs/security-research/unintentional-leak-glimpse-attack-vectors-apt37
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_hh_susp_execution.yml
rules:
  - title: Detect Suspicious HH.EXE Execution
    description: Detects execution of hh.exe (Microsoft HTML Help) when the provided command line points to files in temporary or user-writable directories
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to SIEM/EDR
      owner: Detection Engineering
      due: 48h
      evidence: Rule addresses documented TTPs of hh.exe abuse
  mitigation_plan:
    - priority: medium_term
      action: Apply AppLocker or WDAC policies to restrict execution of hh.exe from non-system directories
      owner: IT Operations
      addresses: T1218.001
      evidence: Hardening system binaries
---

The Microsoft HTML Help (hh.exe) executable is a legitimate system utility designed to display compiled HTML help (.chm) files. Threat actors frequently abuse this utility to execute malicious code by triggering the display of specially crafted .chm files containing embedded ActiveX controls or scripts. This technique is often used in the initial access phase to bypass security controls by masquerading malicious activity behind a signed, legitimate Windows binary.

## Attack Chain

1. An attacker crafts a malicious Compiled HTML (.chm) file.
2. The malicious file is delivered to the target host via spearphishing attachment or downloaded from the web.
3. The file is saved in common user-writable or temporary directories (e.g., AppData, Downloads, or Temp).
4. The attacker or user initiates the execution of the .chm file.
5. The Windows system automatically invokes 'hh.exe' to process the file.
6. The embedded malicious scripts or ActiveX controls execute within the context of 'hh.exe', leading to payload execution.

## Recommendation

- Deploy the Sigma rule below to monitor for executions of hh.exe originating from suspicious locations or targeting unconventional file extensions.
- Implement application control or software restriction policies to limit the execution of 'hh.exe' if it is not required for specific business functions.
- Monitor for suspicious child processes spawned by 'hh.exe', which often indicate secondary payload execution.

## Impact

Successful exploitation allows for the execution of arbitrary code, potentially leading to unauthorized system access, data exfiltration, or the installation of persistent backdoors and banking trojans.
