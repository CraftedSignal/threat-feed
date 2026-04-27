---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-03-trivy-action-compromise
description: The trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines, was compromised via git tag repointing to inject a multi-stage credential stealer.
date: "2026-03-30T07:13:10Z"
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
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Execution of trivy-action entrypoint.sh
    description: Detects execution of the entrypoint.sh script from the trivy-action GitHub Action, which could indicate malicious activity if the action is compromised.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Runner Process Discovery
    description: Detects the enumeration of process IDs (PIDs), which is the initial stage in the malicious campaign.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1057
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike detected suspicious script execution activity originating from GitHub Actions runners across multiple customer environments. Investigation revealed that the aquasecurity/trivy-action GitHub Action, a widely used open-source vulnerability scanner within CI/CD pipelines, had been compromised. Further analysis showed that 76 out of 77 release tags for the action were retroactively poisoned through git tag repointing. This injected malicious code into the action's…
