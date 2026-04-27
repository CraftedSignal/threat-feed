---
title: MOTW Bypass via CAB, TAR, and 7-Zip Chaining
slug: 2026-03-motw-bypass
description: A newly discovered Mark of the Web (MOTW) bypass technique utilizes a chain of CAB, TAR, and 7-Zip archives to circumvent SmartScreen and execute files without security warnings.
date: "2026-03-19T17:31:15Z"
severities:
  - high
tags:
  - motw
  - bypass
  - phishing
  - defense-evasion
  - archive
  - 7-zip
  - cab
  - tar
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1553
    technique_name: Subvert Trust Relationship
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationship
references:
  - https://www.reddit.com/r/blueteamsec/comments/1ry6uu9/is_motw_bypass_possible_in_2026/
  - https://youtu.be/pQxiPwGTBL8
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious Archive Chaining
    description: Detects suspicious process chains involving makecab.exe, 7z.exe, and tar.exe which may indicate exploitation of archive chaining vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - windows
  - title: Detect Archive Extraction from Downloaded CAB
    description: Detects archive extraction from CAB files that originated from a download location, indicating a potential MOTW bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A new MOTW bypass technique has emerged that chains a CAB file with two TAR archives nested within a 7-Zip archive. This method effectively strips the Zone.Identifier stream from downloaded files, preventing the display of SmartScreen prompts or security warnings. Many organizations rely on MOTW and SmartScreen as a crucial layer of defense against phishing attacks. This bypass, affecting fully patched environments, allows attackers to execute arbitrary code without the usual security checks…
