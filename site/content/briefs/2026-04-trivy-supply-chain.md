---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-04-trivy-supply-chain
description: The trivy-action GitHub Action was compromised via git tag repointing, where 76 of 77 release tags were retroactively poisoned, leading to a multi-stage credential theft operation discovered following a spike in script execution detections on Linux runners.
date: "2026-03-31T08:36:29Z"
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1133
    technique_name: External Service Instance Hijacking
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects potentially malicious script execution within GitHub Actions runner environments, indicating a possible compromise.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Runner.Worker Process Spawning Shell
    description: Detects Runner.Worker process spawning a shell which is an indicator of command execution within a Github Actions runner.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike detected a spike in script execution on Linux-based GitHub Actions runners. Investigation traced the activity to a compromise of the aquasecurity/trivy-action GitHub Action, a widely used open-source vulnerability scanner in CI/CD pipelines. The compromise involved retroactively poisoning 76 of the scanner's 77 release tags through git tag repointing. This replaced the legitimate entry point with a multi-stage credential stealer. The malicious code ran before the…
