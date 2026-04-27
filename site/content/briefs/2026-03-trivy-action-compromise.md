---
title: Compromised trivy-action GitHub Action Inserts Credential Stealer
slug: 2026-03-trivy-action-compromise
description: A supply chain compromise of the trivy-action GitHub Action resulted in the insertion of a multi-stage credential stealer into CI/CD pipelines, which executes before the legitimate Trivy scanner, silently stealing credentials while allowing the workflow to appear normal.
date: "2026-03-28T08:30:07Z"
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
  - ci/cd
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Process from Trivy Action
    description: Detects suspicious processes spawned from the compromised trivy-action entrypoint.sh in GitHub Actions runners.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Github Actions Runner Enumerating Processes
    description: Detects the enumeration of processes which is the initial stage of the credential stealer.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, a spike in script execution detections on Linux platforms linked to GitHub Actions runners led to the discovery of a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action. The popular open-source vulnerability scanner, commonly used in CI/CD pipelines, was found to have 76 of its 77 release tags retroactively poisoned via git tag repointing. This replacement introduced a multi-stage credential stealer that silently executes before the legitimate Trivy…
