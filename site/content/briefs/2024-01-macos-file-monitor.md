---
title: macOS File Monitoring via Endpoint Security Framework
slug: 2024-01-macos-file-monitor
description: Objective-See details how to create a file monitor for macOS 10.15 using Apple's Endpoint Security Framework to capture file I/O events and process information.
date: "2024-01-02T18:41:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - file-monitoring
  - endpoint-security
  - macos
vendors:
  - Apple
  - Objective-See
products:
  - macOS
  - CleanMyMac
  - Malwarebytes
  - Airo AV
  - FileMonitor.app
  - Ransomwhere?
  - BlockBlock
affected_os:
  - macOS 10.15 (Catalina)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://objective-see.org/blog/blog_0x48.html
rules:
  - title: Detect File Creation by Unsigned Process
    description: Detects file creation events triggered by processes lacking valid code signatures, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - macos
  - title: Detect File Write by Unsigned Process
    description: Detects file write events triggered by processes lacking valid code signatures, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - macos
rules_count: 2
---

This brief examines the creation of a file monitor on macOS 10.15 (Catalina) using Apple's Endpoint Security Framework, as detailed by Objective-See. This framework offers a user-mode interface to a new Endpoint Security Subsystem, providing a simplified API and comprehensive process information. The file monitor can capture file I/O events, file paths, and process details like process ID, path, and code-signing information. Objective-See highlights the limitations of older file monitoring methods like `/dev/fsevents` and OpenBSM, which lack detailed process information or face deprecation. This new framework aims to address these limitations, enabling more robust user-mode security tools. Tools like Ransomwhere? and BlockBlock use file monitoring for detecting ransomware and persistence events respectively, demonstrating its importance in macOS security.

## Attack Chain

1.  Attacker gains initial access to the system (e.g., through exploitation or social engineering).
2.  Attacker executes a malicious binary or script.
3.  The malicious process creates or modifies a file on the system.
4.  The Endpoint Security Framework captures the file I/O event.
5.  The file monitor, leveraging the Endpoint Security Framework, receives a notification about the event.
6.  The file monitor extracts information about the event, including the process ID, path, code-signing information, and the type of file event (e.g., create, write).
7.  Based on the extracted information, the file monitor determines if the event is malicious (e.g., rapid creation of encrypted files, persistence attempt).
8.  The file monitor alerts the user or security system about the malicious activity.

## Impact

A successful attack can lead to various detrimental outcomes, including data encryption by ransomware, persistent malware installation, and unauthorized access to sensitive information. File monitors, such as the one described, aim to detect and prevent such attacks. Without proper file monitoring, malicious activities can go unnoticed, leading to significant data loss, system compromise, and financial damage. The Endpoint Security Framework intends to address the limitations of previous monitoring solutions.

## Recommendation

*   Enable Endpoint Security Framework event collection to monitor file creation events using the `ES_EVENT_TYPE_NOTIFY_CREATE` event type described in the overview.
*   Deploy the Sigma rule for detecting file creation by unsigned processes to identify potentially malicious activity (see Sigma rule below).
*   Monitor for processes with missing or invalid code-signing information, as these may be indicators of malicious activity, using the Endpoint Security Framework's process information detailed in the overview.
