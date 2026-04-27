---
title: Compromised aquasecurity/trivy-action GitHub Action
slug: 2026-03-trivy-action-supply-chain
description: Attackers poisoned 76 of 77 release tags of the aquasecurity/trivy-action GitHub Action by repointing them to malicious commits containing a multi-stage credential stealer that exfiltrates secrets, credentials, and allows undetected access to infrastructure in CI/CD pipelines.
date: "2026-03-30T21:48:14Z"
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Trivy Action Entrypoint Modification
    description: Detects modifications to the trivy-action entrypoint.sh script, indicating a potential supply chain compromise.
    platform: sigma
    severity: high
    tactics:
      - supply_chain
    techniques:
      - T1195
    data_sources:
      - file_event
      - linux
  - title: Detect Script Execution in GitHub Actions Temp Directory
    description: Detects execution of shell scripts from the GitHub Actions temporary directory, which could indicate malicious activity.
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

On March 19, 2026, CrowdStrike's Engineering team identified a supply chain attack targeting the aquasecurity/trivy-action GitHub Action, a widely used open-source vulnerability scanner in CI/CD pipelines. The attackers retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits. This meant that any CI/CD pipeline using the compromised action would unknowingly execute malicious code before the legitimate Trivy scanner. This malicious code consisted of a multi-stage…
