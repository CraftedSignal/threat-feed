---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-04-trivy-action-compromise
description: The trivy-action GitHub Action, a widely used vulnerability scanner in CI/CD pipelines, was compromised via git tag repointing to inject a multi-stage credential stealer, affecting 76 of 77 release tags.
date: "2026-03-31T06:07:07Z"
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Process Enumeration on GitHub Actions Runner
    description: Detects potential credential theft activity by monitoring for process enumeration commands commonly used by attackers after compromising a CI/CD runner
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Entrypoint Script Execution in trivy-action
    description: Detects execution of the compromised entrypoint.sh script within the trivy-action GitHub Action.
    platform: sigma
    severity: high
    tactics:
      - supply_chain
    techniques:
      - T1199
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike detected a spike in suspicious script executions on Linux-based GitHub Actions runners, which led to the discovery of a supply chain compromise affecting the `aquasecurity/trivy-action` GitHub Action. This action is a popular open-source vulnerability scanner frequently used in CI/CD pipelines. The attacker retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits. These commits replaced the legitimate entry point with a multi-stage…
