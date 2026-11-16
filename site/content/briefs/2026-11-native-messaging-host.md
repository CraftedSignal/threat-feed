---
brief_id: brief-2026-11-16-native-messaging-host
event_id: brief-2026-11-16-native-messaging-host
revision: 1
activity_at: "2026-11-16T17:30:44Z"
title: Chromium Browser Native Messaging Host Misuse
slug: 2026-11-native-messaging-host
description: Attackers can achieve persistence and command-and-control by registering malicious Native Messaging Hosts in the Windows Registry to trigger arbitrary code execution outside the browser sandbox.
date: "2026-11-16T17:30:44Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic defined based on provided Splunk query
tags:
  - persistence
  - command-and-control
  - browser-hijacking
  - endpoint
products:
  - Google Chrome
  - Microsoft Edge
affected_os:
  - Windows
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_native_messaging_host_registered_by_user_writable_binary.yml
rules:
  - title: Detect Windows Native Messaging Host Registration from Suspicious Paths
    description: Detects the creation or modification of Chrome or Edge NativeMessagingHosts registry keys by binaries located in user-writable or common temp directories, which is a technique used for browser-based persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor Registry Event ID 13 for unauthorized NativeMessagingHosts key modifications.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Identify existing registered native messaging hosts and audit their associated binary file paths for signs of unusual activity or untrusted origin.
      technique_id: T1176.001
      data_needed:
        - Registry key values for HKLM and HKCU \NativeMessagingHosts\
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Registering a native messaging host manifest lets a malicious browser extension launch arbitrary local programs.
---

## Overview
Chromium-based browsers (Chrome and Edge) support a Native Messaging feature that allows extensions to communicate with native applications. Attackers exploit this feature by creating or modifying registry keys under the 'NativeMessagingHosts' path, pointing to a binary they control. When a malicious browser extension is loaded, it can launch this registered binary, effectively bypassing the browser's security sandbox to run arbitrary code on the local system. This technique is primarily used for persistence and command-and-control (C2) operations.

## Impact
Successful exploitation allows an attacker to execute arbitrary local programs each time a browser extension connects, resulting in persistent code execution outside the browser's sandbox environment.

## Recommendation
- Implement monitoring for registry modifications (Sysmon Event ID 13) specifically targeting the 'NativeMessagingHosts' keys for Chrome and Edge.
- Baseline and document all legitimate native messaging hosts in your environment to distinguish them from malicious registrations.
- Alert on any new 'NativeMessagingHosts' registry keys created or modified by processes executing from user-writable paths like C:\Users, C:\ProgramData, or C:\PerfLogs.
- Investigate browser extension activity that requires native host communication, particularly when the host binary location is unconventional.
