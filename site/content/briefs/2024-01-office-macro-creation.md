---
title: Detection of Office Macro File Creation
slug: 2024-01-office-macro-creation
description: This brief outlines a threat involving the creation of new Office macro files, potentially indicating malicious activity such as phishing or malware distribution, targeting Windows systems.
date: "2024-01-02T12:00:00Z"
severities:
  - medium
tags:
  - initial-access
  - phishing
  - macro
vendors:
  - Microsoft
products:
  - Microsoft Office
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1566.001/T1566.001.md
  - https://learn.microsoft.com/en-us/deployoffice/compat/office-file-format-reference
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_office_macro_files_created.yml
rules:
  - title: Office Macro File Creation
    description: Detects the creation of new office macro files on the systems
    platform: sigma
    severity: low
    tactics:
      - initial-access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
  - title: Suspicious Process Creating Office Macro File
    description: Detects the creation of office macro files by non-office applications
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The creation of Office macro files (.docm, .xlsm, .pptm, etc.) can be an indicator of malicious activity, often linked to initial access attempts such as phishing campaigns or malware distribution. Attackers frequently embed malicious macros within these files to execute arbitrary code on a victim's machine upon opening the document and enabling macros. While legitimate use cases for macro-enabled documents exist, their creation should be monitored, especially when originating from unusual…
