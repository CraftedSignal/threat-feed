---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-03-trivy-action-supply-chain
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, injecting a multi-stage credential stealer into CI/CD pipelines, allowing for the theft of secrets and credentials.
date: "2026-03-30T06:24:43Z"
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
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects suspicious bash scripts being executed within the GitHub Actions runner environment, potentially indicating malicious activity injected through a compromised action.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Trivy Action Entrypoint Modification
    description: Detects modifications to the entrypoint.sh script within the aquasecurity/trivy-action directory, indicating potential tampering or malicious code injection.
    platform: sigma
    severity: medium
    tactics:
      - integrity
    techniques:
      - T1588.002
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike's Engineering team discovered a supply chain compromise targeting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines. The attackers retroactively poisoned 76 of the scanner’s 77 release tags using git tag repointing, replacing the original entry point with a multi-stage credential stealer. The malicious code operates before the legitimate scanner, masking its activity and allowing workflows to appear…
