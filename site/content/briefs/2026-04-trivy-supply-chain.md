---
title: Compromised trivy-action GitHub Action Enables Credential Theft
slug: 2026-04-trivy-supply-chain
description: A supply chain attack compromised the aquasecurity/trivy-action GitHub Action. By retroactively poisoning release tags via git tag repointing, malicious code was injected into the entry point script. This allowed the attackers to execute a multi-stage credential theft operation on Linux runners before the legitimate Trivy scanner logic, enabling them to steal secrets and credentials from affected CI/CD pipelines.
date: "2026-03-31T01:49:03Z"
severities:
  - critical
tags:
  - supply-chain
  - credential-theft
  - github-actions
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Drive-by Compromise
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Execution of Trivy Action Entrypoint Script
    description: Detects execution of the entrypoint.sh script within the trivy-action directory, which could indicate a supply chain compromise.
    platform: sigma
    severity: high
    tactics:
      - supply_chain
    techniques:
      - T1195
    data_sources:
      - process_creation
      - linux
  - title: Detect Runner.Worker Spawning Suspicious Bash Scripts
    description: Detects the Runner.Worker process spawning bash scripts from the _temp directory, which is indicative of GitHub Actions execution and potentially malicious activity if unexpected.
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

On March 19, 2026, CrowdStrike discovered a supply chain attack targeting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner widely used in CI/CD pipelines. The attackers compromised the action by retroactively poisoning 76 of the 77 release tags through git tag repointing. This replaced the legitimate entry point script with a malicious, multi-stage credential stealer. The malicious code was designed to execute silently before the legitimate Trivy scanner…
