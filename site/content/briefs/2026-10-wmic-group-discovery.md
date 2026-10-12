---
title: Detection of Local Group Discovery via WMIC
slug: 2026-10-wmic-group-discovery
description: Adversaries use wmic.exe to enumerate local groups on Windows endpoints to identify targets for privilege escalation and lateral movement.
date: "2026-10-12T18:25:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - windows
  - wmic
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: The following analytic identifies the use of wmic.exe to enumerate local groups on an endpoint.
    confidence_band: high
rules:
  - title: Detect WMIC Local Group Discovery
    description: Detects the use of wmic.exe to enumerate local groups by monitoring for the 'group get name' command line pattern
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule for wmic group discovery
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic logic for T1069.001
  hunt_leads:
    - lead: Search for historical execution of 'wmic group get name' across the fleet
      technique_id: T1069.001
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Analytic story documentation
---

This brief details a reconnaissance technique where adversaries utilize the Windows Management Instrumentation Command-line (WMIC) tool to perform local group discovery. By executing specific queries via wmic.exe, threat actors can map out existing user groups on a compromised system. This activity is a common precursor to more advanced operations, such as identifying accounts with excessive privileges for lateral movement or targeting specific users for credential theft and privilege escalation. Defenders should focus on command-line telemetry to distinguish this reconnaissance behavior from legitimate administrative troubleshooting. 

## Impact

Successful execution of this discovery technique provides attackers with critical visibility into the host environment's security structure. By identifying privileged groups, attackers can refine their path toward persistence and further unauthorized access, effectively lowering the barrier for subsequent privilege escalation or lateral movement across the network.

## Recommendation

Detection engineering teams should focus on identifying suspicious command-line patterns related to group enumeration. 

- Deploy the provided Sigma rule to detect wmic.exe usage aimed at group enumeration.
- Baseline administrative usage of WMIC within the environment to reduce false positives from system administrators or automated management scripts.
- Ensure that EDR or Sysmon telemetry is configured to capture full command-line arguments to facilitate this detection.
