---
title: Compromised trivy-action GitHub Action Enables Credential Theft
slug: 2026-03-trivy-supply-chain
description: The trivy-action GitHub Action was compromised via git tag repointing, injecting a multi-stage credential stealer that ran before the legitimate scanner, impacting CI/CD pipelines.
date: "2026-03-30T06:42:19Z"
severities:
  - critical
tags:
  - supply-chain
  - credential-theft
  - github-actions
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runners
    description: Detects suspicious script execution originating from GitHub Actions runners, potentially indicating a compromised action.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Trivy Action
    description: Detects malicious activity within the trivy-action directory, indicating a compromised action.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - supply_chain
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, a spike in script execution detections on Linux platforms linked to GitHub Actions runners led CrowdStrike to investigate a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action. This popular open-source vulnerability scanner is widely used in CI/CD pipelines. The investigation revealed that 76 of the scanner's 77 release tags had been retroactively poisoned via git tag repointing. This replaced the legitimate entry point with a multi-stage credential…
