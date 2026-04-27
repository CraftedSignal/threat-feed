---
title: Compromised trivy-action GitHub Action Enables Credential Theft
slug: 2026-03-trivy-action-compromise
description: The trivy-action GitHub Action was compromised via git tag repointing, with attackers poisoning 76 of 77 release tags to inject a multi-stage credential stealer before the legitimate scanner runs, granting attackers access to CI/CD pipeline secrets.
date: "2026-03-28T08:12:22Z"
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
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects execution of potentially malicious scripts within GitHub Actions runners, indicating a possible compromise or unauthorized activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Runner Process Discovery
    description: Detects enumeration of process IDs (PIDs), which is used for runner process discovery and is part of the credential theft operation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, a spike in script execution detections on Linux-based GitHub Actions runners led to the discovery of a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action. The attackers retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits. This manipulation replaced the legitimate entry point with a multi-stage credential stealer. The malicious code operates silently before the legitimate Trivy scanner logic is executed, which…
