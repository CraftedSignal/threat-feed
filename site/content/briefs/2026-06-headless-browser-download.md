---
title: Potential File Download via a Headless Browser
slug: 2026-06-headless-browser-download
description: Detects the execution of headless browsers from suspicious parent processes with arguments indicative of scripted retrieval, bypassing application control policies and restrictions on direct download tools.
date: "2026-04-06T15:34:19Z"
severities:
  - high
tags:
  - command-and-control
  - headless-browser
  - file-download
  - windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Msedge/
rules:
  - title: Detect Headless Browser Download from Suspicious Parent
    description: Detects headless browser execution from a suspicious parent process with arguments consistent with scripted retrieval.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Headless Browser Network Connection
    description: Detects network connections from headless browser processes
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection identifies potential file downloads via headless browsers on Windows systems. Attackers abuse headless browser capabilities (chrome.exe, msedge.exe, brave.exe, browser.exe, dragon.exe, vivaldi.exe) to download files, proxy traffic, and bypass application control policies. The technique leverages trusted, signed binaries to evade security restrictions, effectively using the browser as a covert download tool. The activity is characterized by a headless browser being launched from a…
