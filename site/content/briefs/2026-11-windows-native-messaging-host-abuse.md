---
brief_id: brief-2026-11-16-windows-native-messaging-host-abuse
event_id: brief-2026-11-16-windows-native-messaging-host-abuse
revision: 1
activity_at: "2026-11-16T17:30:52Z"
title: Windows Native Messaging Host Spawns User Writable Process
slug: 2026-11-windows-native-messaging-host-abuse
description: The Splunk analytic detects processes spawned by cmd.exe acting as a Chromium native messaging host launcher from user-writable directories, a technique that can be used by attackers to establish command and control or persistence through malicious browser extensions.
date: "2026-11-16T17:30:52Z"
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
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1176
    technique_name: Browser Extensions
    evidence: Attackers register a malicious native messaging host so that a browser extension can run batch scripts and binaries on demand, giving them a stealthy command and control and persistence channel.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.003
    subtechnique_name: Windows Command Shell
    evidence: The following analytic detects a process located in a user-writable directory (C:\Users, C:\ProgramData or C:\PerfLogs) that is spawned by cmd.exe acting as a Chromium native messaging host launcher.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_native_messaging_host_spawns_user_writable_process.yml
  - https://attack.mitre.org/techniques/T1176/001/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://specterops.io/blog/2026/08/13/chromium-extension-c2-persistence/
  - https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
rules:
  - title: Windows Native Messaging Host Spawns User Writable Process
    description: The analytic detects a process located in a user-writable directory (C:\Users, C:\ProgramData or C:\PerfLogs) that is spawned by cmd.exe acting as a Chromium native messaging host launcher.
    platform: sigma
    severity: medium
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

## Overview

Attackers can register a malicious native messaging host to allow a browser extension to execute batch scripts and binaries, such as a bundled Python interpreter, on demand. This analytic detects when a process, located in a user-writable directory (C:\Users, C:\ProgramData, or C:\PerfLogs), is spawned by cmd.exe acting as a Chromium native messaging host launcher.

## Attack Chain

1. A browser extension triggers a registered native messaging host.
2. The host launcher (cmd.exe) is invoked.
3. The launcher executes a binary or script located in a user-writable directory.

## Impact

If confirmed malicious, this activity allows an attacker to execute arbitrary commands, perform discovery, and run further payloads under the context of the logged-in user.

## Recommendation

Validate identified browser extensions and native host configurations. Known legitimate native hosts should be excluded from detection. Ensure telemetry for process creation (including command-line arguments) is ingested and mapped to the Endpoint data model.
