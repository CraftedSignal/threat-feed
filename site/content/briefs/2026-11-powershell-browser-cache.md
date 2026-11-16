---
brief_id: brief-2026-11-16-powershell-browser-cache
event_id: brief-2026-11-16-powershell-browser-cache
revision: 1
activity_at: "2026-11-16T04:20:17Z"
title: 'Windows PowerShell: Browser Cache Access Detection'
slug: 2026-11-powershell-browser-cache
description: This analytic detects PowerShell Script Block Logging (Event ID 4104) events that enumerate or read browser cache directories, which may indicate cache smuggling where web content is extracted and staged for execution.
date: "2026-11-16T04:20:17Z"
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
  likelihood: roughly even chance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: This analytic detects PowerShell Script Block Logging events that enumerate or read browser cache directories.
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027.006
    technique_name: HTML Smuggling
    evidence: PowerShell inspecting Firefox, Chrome, Edge, Brave, or Chromium cache files can indicate cache smuggling, where web content disguised as an image is extracted and staged for execution.
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_powershell_script_block_browser_cache_access.yml
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1105/
  - https://attack.mitre.org/techniques/T1027/006/
  - https://sensepost.com/blog/2023/browsers-cache-smuggling/
  - https://x.com/MsftSecIntel/status/2106197481960706155
rules:
  - title: Windows PowerShell Script Block Browser Cache Access
    description: This analytic detects PowerShell Script Block Logging events that enumerate or read browser cache directories to identify potential cache smuggling activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1027.006
      - T1059.001
    data_sources:
      - powershell
      - windows
      - powershell
rules_count: 1
---

## Overview
This analytic detects PowerShell Script Block Logging (Event ID 4104) events that enumerate or read browser cache directories for Firefox, Chrome, Edge, Brave, or Chromium. PowerShell inspecting these cache files can indicate cache smuggling, where web content disguised as an image is extracted and staged for execution.

## Attack Chain
- Execution: PowerShell script block interaction with browser cache file paths using cmdlets for enumeration or file reading.
- Defense Evasion: Utilization of browser cache as a staging area for web-delivered content.

## Impact
Potential for bypassing traditional file-based delivery and execution detection mechanisms through the use of browser-staged web content.

## Recommendation
Enable PowerShell Script Block Logging (EventCode 4104) on endpoints to capture script execution. Review script content, user, host, and any subsequent file creation or script execution before disposition, as administrators or support scripts may inspect browser caches for troubleshooting, cleanup, or forensic analysis.
