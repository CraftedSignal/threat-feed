---
title: Detecting Long-Duration Network Connections via macOS Osascript
slug: 2026-09-osascript-long-duration
description: Adversaries may abuse the native 'osascript' utility on macOS to establish long-lived command-and-control channels or remote network connections, which can be identified by analyzing flow duration metadata.
date: "2026-09-21T19:09:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - macos
  - lotl
  - c2
  - osascript
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries may abuse osascript and AppleScript shell execution to establish long-lived command-and-control or remote connections.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Adversaries may abuse osascript and AppleScript shell execution to establish long-lived command-and-control or remote connections.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1059/002/
  - https://attack.mitre.org/techniques/T1071/001/
  - https://www.loobins.io/binaries/osascript/
rules:
  - title: Detect Long-Duration Network Connections via Osascript
    description: Detects usage of osascript that initiates a network connection lasting longer than 10 minutes (600 seconds), which may indicate persistent C2.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.002
      - T1071.001
    data_sources:
      - network_connection
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify all osascript network flows > 10 minutes over the last 30 days.
      technique_id: T1059.002
      data_needed:
        - Cisco NVM flow data
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Analytic detects usage of osascript on a macOS device initiated a network connection lasting longer than 10 minutes.
---

Adversaries targeting macOS environments may abuse the native `osascript` utility to execute AppleScript, facilitating various post-exploitation activities including the establishment of persistent command-and-control (C2) or remote connections. Because `osascript` is a built-in utility, its use is common in administrative scripting and automation, making it a "living-off-the-land" (LotL) binary. This detection identifies anomalous activity where `osascript` initiates network connections that persist for an unusually long duration, specifically exceeding 10 minutes (600 seconds). By leveraging Cisco Network Visibility Module (NVM) flow data, defenders can baseline expected script behavior and flag outliers that may indicate established beaconing or unauthorized remote access.

## Impact

Successful abuse of `osascript` for long-term C2 can lead to persistent unauthorized access to macOS endpoints, facilitating data exfiltration, lateral movement, or further payload deployment. Because the connection is persistent, it increases the likelihood of data staging and successful exfiltration before detection.

## Recommendation

Detection engineering teams should implement monitoring for long-lived processes using the Cisco Network Visibility Module.

* Deploy the provided Sigma rule (or equivalent SIEM logic) to monitor Cisco NVM flow data for `osascript` processes with durations exceeding 600 seconds.
* Baseline current organizational use of `osascript` within administrative workflows to identify and filter out legitimate long-running scripts, reducing false positives.
* Integrate flow data with endpoint process telemetry to provide context on the parent process that invoked `osascript`.
