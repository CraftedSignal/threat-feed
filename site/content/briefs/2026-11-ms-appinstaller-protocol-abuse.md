---
brief_id: brief-2026-11-18-ms-appinstaller-protocol-abuse
event_id: brief-2026-11-18-ms-appinstaller-protocol-abuse
revision: 1
activity_at: "2026-11-18T13:51:00Z"
title: Potential File Download Via MS-AppInstaller Protocol Handler
slug: 2026-11-ms-appinstaller-protocol-abuse
description: The ms-appinstaller protocol handler can be invoked via the command line to potentially facilitate the download of arbitrary files.
date: "2026-11-18T13:51:00Z"
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
tags:
  - attack.execution
  - attack.stealth
  - attack.t1218
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: The ms-appinstaller protocol handler can be used via the command line to potentially download arbitrary files.
references:
  - https://lolbas-project.github.io/lolbas/Binaries/AppInstaller/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_ms_appinstaller_download.yml
rules:
  - title: Potential File Download Via MS-AppInstaller Protocol Handler
    description: Detects usage of the 'ms-appinstaller' protocol handler via command line to potentially download arbitrary files.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - stealth
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

## Overview
The ms-appinstaller protocol handler can be utilized via the command line to potentially facilitate the download of arbitrary files. Files downloaded through this mechanism are stored temporarily in the directory: :\Users\%username%\AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AC\INetCache\&lt;RANDOM-8-CHAR-DIRECTORY>.

## Impact
Potential unauthorized file download and caching of remote content.

## Recommendation
Monitor process creation events for command-line usage containing 'ms-appinstaller://?source=' and 'http'.
