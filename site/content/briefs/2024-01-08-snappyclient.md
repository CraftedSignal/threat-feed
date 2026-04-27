---
title: SnappyClient Malware Delivered via HijackLoader
slug: 2024-01-08-snappyclient
description: SnappyClient is a multi-functional malware delivered via HijackLoader that steals data from browsers, takes screenshots, logs keystrokes, and establishes a remote terminal for attacker command and control.
date: "2026-03-20T05:19:06Z"
severities:
  - high
tags:
  - snappyclient
  - hijackloader
  - malware
  - infostealer
  - keylogger
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1056
    technique_name: Input Capture
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1115
    technique_name: Clipboard Data
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rynlw6/technical_analysis_of_snappyclient_delivered/
  - https://www.zscaler.com/blogs/security-research/technical-analysis-snappyclient
rules:
  - title: Detect Screenshot Capture via Cmd
    description: Detects screenshot capture attempts via command line
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1113
    data_sources:
      - process_creation
      - windows
  - title: Detect Keystroke Logging via PowerShell
    description: Detects potential keystroke logging activity using PowerShell.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1056
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

SnappyClient is a sophisticated malware delivered via HijackLoader, a known malware distribution platform. The malware exhibits a wide array of capabilities, indicative of its intent to compromise systems and exfiltrate sensitive data. These capabilities include screenshot capture, keylogging, establishing a remote terminal for interactive command execution, and targeted data theft from web browsers, browser extensions, and other applications. The combination of these functions points towards a…
