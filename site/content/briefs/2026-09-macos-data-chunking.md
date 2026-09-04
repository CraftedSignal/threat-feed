---
title: Detection of macOS Data Chunking Activities
slug: 2026-09-macos-data-chunking
description: This brief identifies potential data exfiltration by detecting the use of 'split' and 'dd' utilities to segment files for evasion of security controls on macOS endpoints.
date: "2026-09-04T18:01:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - exfiltration
  - macos
  - endpoint
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1030
    technique_name: Data Transfer Size Limits
    evidence: Attackers may use this technique to bypass size-based security controls, facilitating the covert exfiltration of sensitive data.
    confidence_band: high
rules:
  - title: Detect macOS Data Chunking via split or dd
    description: Detects the use of dd or split commands to segment files, which may indicate an attempt to evade security controls during data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1030
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor for dd/split execution patterns on macOS
      owner: Detection Engineering
      due: 72h
      evidence: Source analytic logic for MacOS Data Chunking
  hunt_leads:
    - lead: Identify long-running processes using split or dd that lack associated administrative tickets
      technique_id: T1030
      data_needed:
        - Process command line
        - User context
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analysts should investigate instances where these utilities are executed in suspicious contexts
---

Attackers targeting macOS systems often attempt to exfiltrate sensitive data while evading size-based security controls or network inspection triggers. A common technique involves the use of native system utilities, such as 'split' or 'dd', to break large files into smaller, more manageable chunks. This behavior allows attackers to bypass security appliances or detection rules that alert on large data transfers. This activity is often associated with the post-exploitation phase where an attacker seeks to move proprietary information outside the organization's network perimeter. Security teams should monitor for the execution of these commands, particularly when initiated from non-standard directories or by unauthorized users, as this is a precursor to successful data exfiltration.

## Impact

Successful data chunking and subsequent exfiltration can lead to the unauthorized transfer of sensitive intellectual property, personally identifiable information, or credentials. If attackers bypass size-based network egress filters, they can systematically move data out of the environment without generating high-volume traffic alerts, potentially leading to long-term data loss or compliance breaches.

## Recommendation

Deploy the provided Sigma detection rule to your SIEM and configure log aggregation for process execution data via osquery on macOS endpoints. Evaluate existing administrative workflows to identify and filter benign usage of 'split' and 'dd' to minimize false positives.

- Enable process auditing on macOS via endpoint security APIs and osquery to populate the required telemetry fields.
- Tune the detection logic by incorporating an allowlist for known administrative or backup scripts.
