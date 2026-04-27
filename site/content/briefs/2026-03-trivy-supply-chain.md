---
title: Compromised trivy-action GitHub Action via Git Tag Repointing
slug: 2026-03-trivy-supply-chain
description: The trivy-action GitHub Action was compromised via git tag repointing, where 76 of 77 release tags were retroactively poisoned, replacing the legitimate entry point with a credential stealer that ran silently before the real scanner, targeting GitHub Actions runners on Linux.
date: "2026-03-28T08:17:27Z"
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
    technique_id: T1133
    technique_name: External Service
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects suspicious shell script execution within GitHub Actions runner environments, potentially indicating malicious activity originating from compromised actions.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Trivy Action Entrypoint Execution
    description: Detects execution of the trivy-action entrypoint.sh script, which may indicate a compromised action is being used.
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

On March 19, 2026, CrowdStrike observed a spike in script execution detections on Linux GitHub Actions runners, tracing the activity to a compromised GitHub Action named `aquasecurity/trivy-action`. This popular open-source vulnerability scanner is widely used in CI/CD pipelines. The investigation revealed that 76 of the scanner’s 77 release tags were retroactively poisoned through git tag repointing. This malicious modification replaced the legitimate entry point with a multi-stage…
