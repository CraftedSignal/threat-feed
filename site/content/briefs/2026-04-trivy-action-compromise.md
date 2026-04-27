---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-04-trivy-action-compromise
description: A supply chain compromise of the trivy-action GitHub Action was discovered, where 76 of the 77 release tags had been retroactively poisoned to include a multi-stage credential stealer that runs before the legitimate scanner, making workflows appear normal.
date: "2026-03-31T17:50:16Z"
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
  - title: Detect Malicious Trivy Action Entrypoint Execution
    description: Detects the execution of the malicious entrypoint.sh script within the trivy-action GitHub Action, indicating a potential supply chain compromise.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect GitHub Actions Runner Enumerating Processes
    description: Detects a GitHub Actions runner enumerating running processes, which is a stage in the malicious Trivy Action.
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

On March 19, 2026, a spike in suspicious script executions on Linux platforms linked to GitHub Actions runners was observed, leading to the discovery of a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action. The popular open-source vulnerability scanner had 76 of its 77 release tags retroactively poisoned via git tag repointing. This involved replacing the legitimate entry point with a multi-stage credential stealer. The malicious code executed before the legitimate…
