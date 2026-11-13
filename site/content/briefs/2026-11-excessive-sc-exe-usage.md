---
brief_id: brief-2026-11-13-excessive-sc-exe-usage
event_id: brief-2026-11-13-excessive-sc-exe-usage
revision: 1
activity_at: "2026-11-13T15:54:39Z"
title: Excessive sc.exe Service Utility Execution
slug: 2026-11-excessive-sc-exe-usage
description: This detection identifies anomalous, high-frequency usage of the sc.exe service utility, which may be associated with malware attempting to manipulate system services.
date: "2026-11-13T15:54:39Z"
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
tags:
  - ransomware
  - defense-evasion
affected_os:
  - Windows
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/excessive_usage_of_sc_service_utility.yml
  - https://app.any.run/tasks/c0f98850-af65-4352-9746-fbebadee4f05/
rules:
  - title: Excessive sc.exe Execution
    description: Detects excessive usage of sc.exe by counting unique process GUIDs in 15-minute windows where the count is greater than five and exceeds the host's historical average plus three standard deviations.
    platform: sigma
    severity: medium
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

The sc.exe service utility is used to interact with the Windows Service Control Manager. This detection monitors for excessive executions of sc.exe on a host within 15-minute windows, specifically flagging activity that exceeds five executions and is at or above the host's historical average count plus three standard deviations. This behavior is associated with ransomware, cryptocurrency miners, and other malware attempting to create, modify, delete, or disable services.

## Impact
If confirmed malicious, this activity could allow attackers to manipulate critical services, potentially leading to system compromise or the disruption of security defenses.

## Recommendation
To implement this, ingest endpoint process creation events and map them to the Endpoint.Processes data model. If using Sysmon, use at least version 6.0.4. Monitor for frequent executions of sc.exe and tune results to account for legitimate software installation, endpoint management, or administrative scripts.
