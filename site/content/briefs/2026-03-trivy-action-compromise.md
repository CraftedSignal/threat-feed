---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-03-trivy-action-compromise
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, injecting a multi-stage credential stealer into CI/CD pipelines, potentially exposing secrets, credentials, and infrastructure.
date: "2026-03-30T07:26:38Z"
type: coverage
types:
  - coverage
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

On March 19, 2026, CrowdStrike's Engineering team identified a supply chain attack targeting the widely used aquasecurity/trivy-action GitHub Action. The attackers retroactively poisoned 76 of 77 release tags by repointing them to malicious commits, effectively replacing the legitimate entry point with a multi-stage credential stealer. This compromised action, typically used for vulnerability scanning in CI/CD pipelines, injected malicious code before the genuine scanner logic, maintaining a facade of normal operation. The impact of this compromise extends to any pipeline referencing the poisoned versions, granting the attackers potential access to secrets, credentials, and internal infrastructure configured within the GitHub Actions environment. Aqua Security has confirmed the compromise and removed the malicious artifacts.

## Attack Chain

1.  **Initial Access:** Attackers gained write access to the aquasecurity/trivy-action GitHub repository.
2.  **Tag Repointing:** Malicious actors repointed existing git tags (e.g., `@0.24.0`) to malicious commits containing the injected credential-stealing code.
3.  **Workflow Execution:** Developers trigger CI/CD workflows that reference the compromised trivy-action by tag.
4.  **Malicious Entrypoint Execution:** The GitHub Actions runner downloads the compromised action and executes the injected malicious code within `entrypoint.sh` before the legitimate Trivy scanner.
5.  **Process Discovery:** The malicious script enumerates process IDs (PIDs) on the runner.
6.  **Credential Theft:** The injected code performs multi-stage credential theft operations, leveraging the runner's environment and access to secrets.
7.  **Normal Execution:** The legitimate Trivy scanner is executed after the malicious code, masking the compromise and allowing workflows to complete without apparent errors.
8.  **Data Exfiltration:** Stolen credentials and secrets are exfiltrated to an attacker-controlled location (details of exfiltration not specified in source).

## Impact

The compromise of the trivy-action GitHub Action affected numerous CI/CD pipelines relying on the scanner. While the exact number of victims is not specified, the wide adoption of the action suggests a broad impact. Successful exploitation grants attackers access to sensitive credentials, API keys, and cloud deployment tokens configured within the affected pipelines. This access could lead to unauthorized access to internal infrastructure, data breaches, and supply chain attacks targeting downstream dependencies.

## Recommendation

*   Review your CI/CD pipelines for usage of the `aquasecurity/trivy-action` GitHub Action and inspect the commit history of the referenced tags for unexpected changes.
*   Deploy the Sigma rules provided in this brief to detect potential malicious activity originating from GitHub Actions runners.
*   Enable detailed logging on GitHub Actions runners to capture process execution and network connections for incident investigation.
