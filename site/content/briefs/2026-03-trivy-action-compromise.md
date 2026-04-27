---
title: Compromised trivy-action GitHub Action Steals Credentials
slug: 2026-03-trivy-action-compromise
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, where 76 of 77 release tags were retroactively poisoned with malicious code that executes a multi-stage credential theft operation.
date: "2026-03-30T06:19:01Z"
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
  - title: Detect Trivy Action Compromise - Suspicious Script Execution
    description: Detects execution of the malicious entrypoint.sh script associated with the compromised trivy-action GitHub Action.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - process_creation
      - linux
  - title: Detect Trivy Action Compromise - Runner Process Discovery
    description: Detects suspicious script execution indicative of the first stage of the compromised trivy-action GitHub Action, specifically process enumeration.
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

On March 19, 2026, CrowdStrike discovered a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines. The attack involved retroactively poisoning 76 of the 77 release tags via git tag repointing, replacing the legitimate entry point with a multi-stage credential stealer. The malicious code was designed to run silently before the real scanner, allowing workflows to complete normally and evade initial…
