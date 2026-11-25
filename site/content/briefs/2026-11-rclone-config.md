---
brief_id: brief-2026-11-25-rclone-config
event_id: brief-2026-11-25-rclone-config
revision: 1
activity_at: "2026-11-25T16:23:57Z"
title: Rclone configuration file creation
slug: 2026-11-rclone-config
description: The creation of Rclone configuration files on Windows systems may indicate the preparation for data exfiltration activities using the Rclone command-line tool.
date: "2026-11-25T16:23:57Z"
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
  validation_status: Detection logic reviewed against standard Windows file path conventions.
tags:
  - exfiltration
  - rclone
  - windows
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    subtechnique_id: T1567.002
    subtechnique_name: Exfiltration to Cloud Storage
    evidence: Rclone is frequently identified as an effective tool for data exfiltration to cloud providers.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_rclone_config_files.yml
rules:
  - title: Detect Rclone Configuration File Creation
    description: Detects the creation of Rclone configuration files in Windows user profile directories, which is often a precursor to unauthorized data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor FileCreate events targeting Rclone config paths.
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in source.
  hunt_leads:
    - lead: Search for unusual child processes of rclone.exe or high-volume data transfers associated with Rclone executions.
      technique_id: T1567.002
      data_needed:
        - Sysmon Event ID 1 (Process Creation)
        - Network flow logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Rclone usage is inherently tied to exfiltration patterns.
---

## Overview

Rclone is a command-line program for managing files on cloud storage. Threat actors frequently utilize Rclone for data exfiltration due to its extensive cloud provider support and ability to encrypt data in transit. The creation of a configuration file in a user profile directory is a necessary prerequisite for Rclone to authenticate and interact with remote storage services.

## Impact

Unauthorized data exfiltration to attacker-controlled cloud storage, potentially leading to sensitive data loss.

## Recommendation

Deploy the provided Sigma rule to monitor for the creation of Rclone configuration files. In environments where Rclone is not used, treat these file creation events as high-fidelity alerts for potential exfiltration activity. In environments where Rclone is used legitimately, baseline authorized user accounts and service accounts that are permitted to interact with Rclone and investigate deviations.
