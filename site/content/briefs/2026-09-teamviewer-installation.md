---
title: Detection of TeamViewer Desktop Installation
slug: 2026-09-teamviewer-installation
description: This brief documents the detection of TeamViewer Desktop installation via file system activity, often associated with Remote Access Software usage.
date: "2026-09-03T13:36:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - remote-access
  - monitoring
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_install_teamviewer_desktop.yml
rules:
  - title: Detect TeamViewer Desktop Installation
    description: Detects the creation of TeamViewer_Desktop.exe on the file system
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  hunt_leads:
    - lead: Identify all instances of TeamViewer_Desktop.exe in the environment
      technique_id: T1219
      data_needed:
        - Endpoint file scan or EDR inventory
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source provides a detection rule for this file
---

The installation of TeamViewer Desktop involves the creation of the specific executable 'TeamViewer_Desktop.exe' on the Windows file system. While TeamViewer is legitimate remote support software, its unauthorized or unexpected presence in an enterprise environment can be indicative of Remote Access Software usage (MITRE ATT&CK T1219). Defenders should monitor for the creation of this file to identify potentially unauthorized remote access tools installed within the network. This detection is particularly relevant for organizations with strict software control policies where administrative oversight of remote access utilities is required to prevent unauthorized persistence or exfiltration channels.

## Impact

Unauthorized installation of remote access software can provide attackers with persistent, interactive access to internal systems, potentially facilitating data exfiltration, reconnaissance, and command-and-control communication.

## Recommendation

* Deploy the Sigma rule below to monitor for the creation of 'TeamViewer_Desktop.exe' using file integrity monitoring or EDR telemetry.
* Audit authorized software lists and investigate instances where TeamViewer is installed on systems not designated for remote support.
* Correlate this file creation event with network connection logs to identify C2 communication patterns associated with remote access tools.
