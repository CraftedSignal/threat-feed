---
title: Detection of Potentially Unwanted Application Named Pipe Usage
slug: 2026-10-windows-pua-named-pipe
description: This detection analytic identifies the creation or interaction with named pipes associated with potentially unwanted applications (PUAs) or administrative utilities that attackers leverage for lateral movement, command-and-control, or process injection.
date: "2026-10-05T12:26:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - pua
  - lateral-movement
  - c2
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1559
    technique_name: Inter-Process Communication
    evidence: The detection analytic identifies named pipes used by potentially unwanted applications which can be abused for persistence.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1021.002
    technique_name: SMB/Windows Admin Shares
    evidence: The detection covers utilities like PsExec which leverage named pipes for remote execution.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1055
    technique_name: Process Injection
    evidence: Named pipes are a common mechanism used by attackers for process injection.
    confidence_band: med
rules:
  - title: Detect PUA Named Pipe Creation or Connection
    description: Detects the creation or connection to named pipes associated with potentially unwanted applications (PUAs) using Sysmon Event IDs 17 and 18.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - persistence
    techniques:
      - T1559
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable Sysmon Event IDs 17 and 18 logging
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies these as the required data sources.
  hunt_leads:
    - lead: Search for rare named pipe names in the environment that do not map to known enterprise software.
      technique_id: T1559
      data_needed:
        - Sysmon Event ID 17, 18
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Named pipes are a primary vector for inter-process communication abuse.
---

This detection focuses on the abuse of Windows named pipes for inter-process communication by potentially unwanted applications (PUAs) or administrative tools, such as PsExec. Attackers frequently leverage named pipes to facilitate lateral movement, hide command-and-control traffic, or perform process injection. By monitoring Sysmon Event IDs 17 (Pipe Created) and 18 (Pipe Connected), security teams can identify anomalous pipe activity that deviates from standard system or enterprise software baseline behavior. While these pipes are essential for legitimate Windows operations and specific administrative software, their presence in unexpected processes or unusual contexts often indicates malicious activity, including use by ransomware groups and advanced persistent threats (APTs). This analytic is intended to surface these anomalies for further investigation within a security operations platform.

## Impact

Successful abuse of named pipes can enable attackers to move laterally across a network, execute remote commands, and deploy ransomware or other malicious payloads. This visibility is critical for defending against threats documented in various security advisories, including those related to BlackByte, Cactus, Medusa, Rhysida, and VanHelsing ransomware, as well as activity associated with Sandworm and Volt Typhoon.

## Recommendation

* Enable Sysmon logging with Event IDs 17 and 18 on all critical endpoints.
* Deploy the provided detection logic to identify processes accessing named pipes listed in the `pua_named_pipes` lookup table.
* Tune the detection by adding legitimate organization-specific paths to the exclusion filter to minimize noise from enterprise applications.
* Investigate alerts by pivoting to the process metadata and associated user activity to confirm if the interaction is part of authorized administration or malicious behavior.
