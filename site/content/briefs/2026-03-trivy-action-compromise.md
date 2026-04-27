---
title: Compromised trivy-action GitHub Action Injects Credential Stealer
slug: 2026-03-trivy-action-compromise
description: The trivy-action GitHub Action was compromised via tag repointing, injecting a multi-stage credential stealer into CI/CD pipelines, affecting 76 of 77 release tags.
date: "2026-03-21T09:00:00Z"
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects execution of shell scripts from unusual locations within the GitHub Actions runner environment, indicating potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Network Connection from GitHub Actions Runner to Public IP
    description: Detects network connections initiated from GitHub Actions runners to public IP addresses, which could indicate command and control or data exfiltration activity.
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

On March 19, 2026, a spike in script execution detections on Linux platforms was observed across multiple CrowdStrike Falcon customers. Investigation revealed a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines. The attacker retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits, replacing the legitimate entry point with a multi-stage credential stealer. The…
