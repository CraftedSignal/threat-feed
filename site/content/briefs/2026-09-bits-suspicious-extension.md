---
title: Suspicious File Extensions in BITS Transfer Jobs
slug: 2026-09-bits-suspicious-extension
description: Detection of BITS transfer jobs saving files with potentially malicious extensions, a technique used by adversaries to download and execute payloads while evading traditional security monitoring.
date: "2026-09-01T11:05:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - bits
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1197
    technique_name: BITS Jobs
    evidence: Adversaries use BITS jobs to download malicious files to disk.
    confidence_band: high
rules:
  - title: Detect Suspicious File Extensions in BITS Transfer Jobs
    description: Detects new BITS transfer jobs saving local files with potential suspicious extensions like .exe, .dll, or .ps1
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1197
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable Microsoft-Windows-BITS-Client/Operational logging
      owner: IT Operations
      due: 48h
      evidence: Required for Event ID 16403 visibility.
  hunt_leads:
    - lead: Search for historical BITS transfer jobs that completed with suspicious extensions in non-standard paths.
      technique_id: T1197
      data_needed:
        - Event ID 16403
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source provides specific extensions for monitoring.
---

Background Intelligent Transfer Service (BITS) is a legitimate Windows component designed for asynchronous, prioritized, and throttled file transfers. Adversaries frequently abuse BITS to download malicious payloads or exfiltrate data, leveraging its ability to bypass certain proxy configurations and maintain persistence across system reboots. This detection focuses on identifying BITS transfer jobs that result in the creation of files with extensions commonly associated with script execution or binary deployment, such as .exe, .dll, .bat, or .ps1. By monitoring the BITS service logs for specific file extensions being written to disk, defenders can identify potential stage-one malware delivery or secondary payload acquisition that might otherwise blend in with legitimate update traffic.

## Impact

Successful abuse of BITS for payload delivery can lead to remote code execution, persistence establishment, or data exfiltration. Attackers exploit the trusted nature of the BITS service to download malicious files to sensitive directories, potentially bypassing standard application whitelisting or endpoint protection heuristics that prioritize the BITS process over the underlying payload content.

## Recommendation

Deploy the following detection logic to monitor BITS-client event logs for suspicious file write operations. Prior to enabling, tune the exclusions (filters) based on local baselines to account for authorized software update processes, specifically those utilizing standard paths like AppData.

- Deploy the Sigma rule below to track BITS-client Event ID 16403.
- Establish a baseline of legitimate BITS transfers in the environment to refine filtering and reduce false positives.
- Investigate any hits against this rule to confirm if the source (RemoteName) and destination (LocalName) are consistent with expected business operations.
