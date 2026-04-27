---
title: Compromised trivy-action GitHub Action for Credential Theft
slug: 2026-03-trivy-supply-chain
description: A supply chain compromise of the aquasecurity/trivy-action GitHub Action resulted in the insertion of malicious code into 76 out of 77 release tags, silently performing credential theft operations on Linux runners before running the legitimate Trivy scanner.
date: "2026-03-30T22:05:09Z"
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
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Process Enumeration in GitHub Actions
    description: Detects suspicious process enumeration activity within GitHub Actions runners, potentially indicating malicious code execution.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1057
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Trivy Action Entrypoint
    description: Detects modifications to the `entrypoint.sh` script of the aquasecurity/trivy-action GitHub Action with malicious code.
    platform: sigma
    severity: high
    tactics:
      - supply_chain
    techniques:
      - T1195.002
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike's Engineering team detected a spike in script execution on Linux GitHub Actions runners, tracing the activity to a compromised GitHub Action named aquasecurity/trivy-action. This popular open-source vulnerability scanner used in CI/CD pipelines had 76 of its 77 release tags retroactively poisoned via git tag repointing. This replaced the legitimate entry point with a multi-stage credential stealer that ran silently before the real scanner. Aqua Security has…
