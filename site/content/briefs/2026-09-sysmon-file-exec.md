---
title: Detection Capability for Executable File Creation via Sysmon
slug: 2026-09-sysmon-file-exec
description: This brief details a detection capability for monitoring the creation of Portable Executable files using Sysmon Event ID 29 to identify unauthorized binary drops.
date: "2026-09-03T13:35:46Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - windows
  - sysmon
  - detection-engineering
  - defensive-telemetry
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
  - https://medium.com/@olafhartong/sysmon-15-0-file-executable-detected-40fd64349f36
rules:
  - title: Detect Executable File Creation via Sysmon Event 29
    description: Detects the creation of Portable Executable (PE) files logged by Sysmon Event ID 29, which indicates an executable has been written to a monitored path.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Review existing Sysmon configuration to define monitored paths for Event ID 29.
      owner: Detection Engineering
      due: 7d
      evidence: Source documentation on Sysmon Event ID 29.
  mitigation_plan:
    - priority: medium_term
      action: Refine Sysmon configuration to exclude known-good software paths from Event ID 29 monitoring.
      owner: IT Operations
      evidence: False positive list in rule handoff.
---

This brief outlines a detection capability utilizing Sysmon Event ID 29, which specifically logs the creation of Portable Executable (PE) files. This event is generated when a file with a PE signature is written to disk in paths explicitly defined within the Sysmon configuration. Because this event relies heavily on the underlying Sysmon configuration, it is highly sensitive to the scope of paths monitored by the organization. Defenders should treat this as a foundational capability for identifying the delivery of malicious payloads, staging of tools, or persistence mechanisms where an attacker writes a new binary to the filesystem. The detection is intended to serve as a high-signal indicator of activity in sensitive directories; however, it requires careful baseline tuning to differentiate between legitimate software updates or application deployments and actual attacker-initiated executable drops.

## Recommendation

- Deploy the provided Sigma rule to your SIEM to monitor for new executable files in high-risk directories.
- Audit existing Sysmon configuration files to ensure that critical directories such as system root, user profiles, and temporary storage locations are correctly monitored by the FileExecutableDetected filter.
- Implement a tuning process to suppress alerts from known-legitimate software installers by refining the Sysmon filter configuration rather than disabling the rule.
- Enable Sysmon Event ID 29 logging on all Windows endpoints to ensure the telemetry required for this detection is generated and forwarded to the SIEM.
