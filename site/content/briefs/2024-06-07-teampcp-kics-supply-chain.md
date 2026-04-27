---
title: TeamPCP Compromise of KICS GitHub Action Supply Chain
slug: 2024-06-07-teampcp-kics-supply-chain
description: TeamPCP conducted a supply chain attack compromising the KICS GitHub Action, impacting users who integrated the compromised version into their CI/CD pipelines.
date: "2026-03-23T19:20:57Z"
severities:
  - high
actors:
  - TeamPCP
tags:
  - supply-chain
  - github-actions
  - ci/cd
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1005
    technique_name: Data From Local System
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s1qnim/kics_github_action_compromised_teampcp_supply/
  - https://www.wiz.io/blog/teampcp-attack-kics-github-action
rules:
  - title: Detect Script Execution in GitHub Actions Workflow
    description: Detects execution of potentially malicious scripts (e.g., bash, python, powershell) within GitHub Actions workflow jobs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Outbound Network Connection from GitHub Actions Runner
    description: Detects outbound network connections initiated from the GitHub Actions runner to suspicious or unknown IP addresses or domains.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

On March 23, 2026, Wiz.io reported a supply chain attack targeting the KICS (Keeping Infrastructure Configuration Secure) GitHub Action. The threat actor, identified as TeamPCP, successfully compromised the KICS GitHub Action, potentially impacting numerous organizations utilizing the action in their CI/CD pipelines. This incident highlights the risks associated with supply chain dependencies and the potential for malicious actors to inject malicious code into widely used software components…
