---
brief_id: brief-2026-11-10-winget-insecure-source
event_id: brief-2026-11-10-winget-insecure-source
revision: 1
activity_at: "2026-11-10T03:08:00Z"
title: 'Winget: Addition of insecure download source'
slug: 2026-11-winget-insecure-source
description: An attacker may attempt to register an insecure HTTP source within the Windows Package Manager (Winget) to facilitate malicious package delivery.
date: "2026-11-10T03:08:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - winget
  - living-off-the-land
  - execution
affected_os:
  - Windows
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_winget_add_insecure_custom_source.yml
  - https://learn.microsoft.com/en-us/windows/package-manager/winget/source
rules:
  - title: Detect Addition of Insecure Winget Source
    description: Detects the usage of winget to add a package source via insecure HTTP.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to flag insecure configuration attempts.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection logic for insecure winget source usage.
  hunt_leads:
    - lead: Identify hosts where custom Winget sources are currently configured.
      technique_id: T1059
      data_needed:
        - Output of "winget source list" from endpoint management systems
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Winget sources can be configured to point to arbitrary locations.
---

Winget is a command-line utility used to manage software installations on Windows. It is possible to add custom package sources for the tool to fetch software from. Security controls prevent the addition of sources via HTTP due to the risk of man-in-the-middle attacks, but the attempt to add such a source may indicate an attacker testing for misconfigurations or attempting to force a policy bypass.

## Recommendation

- Deploy the provided Sigma rule to detect attempts to register insecure package repositories.
- Audit existing Winget sources via the `winget source list` command to ensure only authorized, HTTPS-enabled repositories are configured.
- Restrict command-line execution permissions for standard users to prevent unauthorized modification of package management configurations.
