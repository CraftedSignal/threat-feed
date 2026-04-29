---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-04-trivy-action-compromise
description: A supply chain compromise of the trivy-action GitHub Action was discovered, where 76 of the 77 release tags had been retroactively poisoned to include a multi-stage credential stealer that runs before the legitimate scanner, making workflows appear normal.
date: "2026-03-31T17:50:16Z"
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
  - title: Detect Malicious Trivy Action Entrypoint Execution
    description: Detects the execution of the malicious entrypoint.sh script within the trivy-action GitHub Action, indicating a potential supply chain compromise.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect GitHub Actions Runner Enumerating Processes
    description: Detects a GitHub Actions runner enumerating running processes, which is a stage in the malicious Trivy Action.
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

On March 19, 2026, a spike in suspicious script executions on Linux platforms linked to GitHub Actions runners was observed, leading to the discovery of a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action. The popular open-source vulnerability scanner had 76 of its 77 release tags retroactively poisoned via git tag repointing. This involved replacing the legitimate entry point with a multi-stage credential stealer. The malicious code executed before the legitimate scanner, ensuring workflows appeared to complete without errors. Aqua Security confirmed the compromise of the Trivy GitHub Action script, setup script, and binary and removed the malicious artifacts. This incident highlights the risks associated with trusting third-party actions in CI/CD pipelines and the potential for attackers to exploit the mutability of Git tags.

## Attack Chain

1.  Attacker gains write access to the aquasecurity/trivy-action GitHub repository.
2.  Attacker modifies the entrypoint.sh script to include malicious code for credential theft.
3.  Attacker repoints existing Git tags (e.g., 0.24.0) to the malicious commit, effectively poisoning existing versions.
4.  When a CI/CD pipeline references the compromised trivy-action using a poisoned tag, the GitHub Actions runner downloads and executes the malicious entrypoint.sh.
5.  The malicious script enumerates process IDs (PIDs) to identify potential targets.
6.  The credential stealer extracts sensitive information, such as API keys, deploy tokens, and cloud credentials, from the runner's environment, secrets, and network.
7.  The legitimate Trivy scanner is then executed to mask the malicious activity and ensure the workflow completes successfully.
8.  The stolen credentials can then be used to gain unauthorized access to internal infrastructure or cloud resources.

## Impact

The compromise of the trivy-action GitHub Action potentially impacts numerous organizations that rely on this action for vulnerability scanning in their CI/CD pipelines. The primary impact is the theft of sensitive credentials, which could lead to unauthorized access to internal infrastructure, cloud resources, and sensitive data. The exact number of affected organizations is unknown, but given the popularity of the trivy-action, the potential scope of the compromise is significant. Successful exploitation could result in data breaches, financial losses, and reputational damage.

## Recommendation

*   Inspect GitHub Actions runner logs for suspicious script execution, specifically within the `entrypoint.sh` of the `aquasecurity/trivy-action` as described in the Overview.
*   Deploy the Sigma rule to detect the execution of the malicious `entrypoint.sh` script, which contains a multi-stage credential stealer, within the GitHub Actions runner environment.
*   Monitor for unexpected network connections originating from GitHub Actions runners as a sign of potential data exfiltration after credential compromise, using network connection logs.
*   Pin GitHub Actions to specific commit SHAs instead of relying on tags to avoid tag-repointing attacks, as described in the Overview.
