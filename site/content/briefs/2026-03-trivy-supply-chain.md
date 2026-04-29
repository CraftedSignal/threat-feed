---
title: Compromised trivy-action GitHub Action Enables Credential Theft
slug: 2026-03-trivy-supply-chain
description: The trivy-action GitHub Action was compromised via git tag repointing, injecting a multi-stage credential stealer that ran before the legitimate scanner, impacting CI/CD pipelines.
date: "2026-03-30T06:42:19Z"
type: coverage
types:
  - coverage
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
  - title: Detect Suspicious Script Execution in GitHub Actions Runners
    description: Detects suspicious script execution originating from GitHub Actions runners, potentially indicating a compromised action.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Trivy Action
    description: Detects malicious activity within the trivy-action directory, indicating a compromised action.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - supply_chain
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, a spike in script execution detections on Linux platforms linked to GitHub Actions runners led CrowdStrike to investigate a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action. This popular open-source vulnerability scanner is widely used in CI/CD pipelines. The investigation revealed that 76 of the scanner's 77 release tags had been retroactively poisoned via git tag repointing. This replaced the legitimate entry point with a multi-stage credential stealer. The malicious code was prepended to the legitimate Trivy scanner logic, running silently before it, so workflows appeared to complete normally. CrowdStrike coordinated with Aqua Security, who removed the malicious artifacts from their repositories.

## Attack Chain

1. An attacker compromised the aquasecurity/trivy-action GitHub Action by repointing git tags.
2. The malicious code was injected into the entrypoint.sh script of the trivy-action.
3. When a workflow using the compromised action runs, the runner downloads the modified action from GitHub.
4. The runner executes the malicious code in the entrypoint.sh script.
5. The malicious script enumerates process IDs (PIDs) to discover runner processes.
6. The injected code executes a multi-stage credential theft operation.
7. After the credential theft, the legitimate Trivy scanner logic is executed to mask the malicious activity.
8. Stolen credentials are used to access sensitive resources or conduct further attacks.

## Impact

The compromise of the trivy-action GitHub Action potentially impacted numerous organizations utilizing this action in their CI/CD pipelines. The injected credential stealer could lead to unauthorized access to sensitive resources, including API keys, deploy tokens, cloud credentials, and internal infrastructure. Successful credential theft can result in data breaches, unauthorized deployments, and other malicious activities, depending on the scope of the compromised credentials. The exact number of affected organizations remains unknown, but the widespread adoption of the trivy-action suggests a significant impact.

## Recommendation

*   Examine CI/CD pipeline logs for unusual script execution originating from GitHub Actions runners to detect past compromises using the Sigma rule `Detect Suspicious Script Execution in GitHub Actions Runners`.
*   Monitor process execution on GitHub Actions runners for unexpected processes or command-line arguments, focusing on activity within the `/home/runner/_work/_actions/aquasecurity/trivy-action/` directory using the Sigma rule `Detect Malicious Trivy Action`.
*   Implement integrity checks for GitHub Actions to verify that the code being executed matches the expected version and is free from modifications.
*   Review and restrict the permissions granted to GitHub Actions workflows to minimize the potential impact of credential theft or other malicious activities.
*   Rotate any potentially compromised credentials that were accessible to affected GitHub Actions workflows.
