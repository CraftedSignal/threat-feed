---
title: Compromised trivy-action GitHub Action Steals Credentials
slug: 2026-03-trivy-supply-chain
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, injecting a multi-stage credential stealer into CI/CD pipelines, affecting 76 of 77 release tags.
date: "2026-03-28T09:15:08Z"
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
  - linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects potentially malicious shell scripts executed within a GitHub Actions runner environment, indicating a possible compromise of a GitHub Action.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - process_creation
      - linux
  - title: Detect Process ID Enumeration via ps Command
    description: Detects the use of 'ps' command combined with other utilities to enumerate process IDs, which is the first stage shown in the compromise.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1057
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike's engineering team discovered a supply chain attack targeting the widely-used aquasecurity/trivy-action GitHub Action. This action is a popular open-source vulnerability scanner commonly used in CI/CD pipelines. The attackers compromised the action by retroactively poisoning 76 of the 77 release tags via git tag repointing. This involved replacing the legitimate action's entry point with a malicious multi-stage credential stealer. The malicious code executes…
