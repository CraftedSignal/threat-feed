---
title: Compromised trivy-action GitHub Action
slug: 2026-03-trivy-action-compromise
description: The trivy-action GitHub Action was compromised via git tag repointing, with 76 of 77 release tags poisoned to include a multi-stage credential stealer that executes before the legitimate scanner, impacting CI/CD pipelines.
date: "2026-03-31T09:21:47Z"
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Suspicious Process Execution in GitHub Actions Runner
    description: Detects execution of suspicious processes within the GitHub Actions runner environment, potentially indicating malicious activity injected via a compromised action.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of GitHub Action Entrypoint
    description: Detects modification of the entrypoint.sh file within a GitHub Action directory, which could indicate a supply chain compromise.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1199
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On March 19, 2026, a spike in script execution detections on Linux GitHub Actions runners led to the discovery of a supply chain compromise targeting the aquasecurity/trivy-action GitHub Action. The attack involved retroactively poisoning 76 of the 77 release tags by repointing them to malicious commits. This injected a multi-stage credential stealer into the action's entrypoint.sh script. The malicious code executes before the legitimate Trivy scanner, allowing it to steal credentials and…
