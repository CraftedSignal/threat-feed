---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-03-trivy-action-compromise
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, injecting a multi-stage credential stealer into CI/CD pipelines, potentially exposing secrets, credentials, and infrastructure.
date: "2026-03-30T07:26:38Z"
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
  - title: Detect Execution of Trivy Action Entrypoint Script
    description: Detects execution of the trivy-action entrypoint.sh script, which may indicate the use of the action in a GitHub Actions workflow.
    platform: sigma
    severity: informational
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Runner.Worker Process Spawning Shell
    description: Detects the Runner.Worker process spawning a shell, which is part of the standard execution chain, but can be used as a baseline for detecting further malicious activity.
    platform: sigma
    severity: informational
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike's Engineering team identified a supply chain attack targeting the widely used aquasecurity/trivy-action GitHub Action. The attackers retroactively poisoned 76 of 77 release tags by repointing them to malicious commits, effectively replacing the legitimate entry point with a multi-stage credential stealer. This compromised action, typically used for vulnerability scanning in CI/CD pipelines, injected malicious code before the genuine scanner logic, maintaining a…
