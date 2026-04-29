---
title: Compromised trivy-action GitHub Action Enables Credential Theft
slug: 2026-04-trivy-supply-chain
description: A supply chain attack compromised the aquasecurity/trivy-action GitHub Action. By retroactively poisoning release tags via git tag repointing, malicious code was injected into the entry point script. This allowed the attackers to execute a multi-stage credential theft operation on Linux runners before the legitimate Trivy scanner logic, enabling them to steal secrets and credentials from affected CI/CD pipelines.
date: "2026-03-31T01:49:03Z"
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

On March 19, 2026, CrowdStrike discovered a supply chain attack targeting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner widely used in CI/CD pipelines. The attackers compromised the action by retroactively poisoning 76 of the 77 release tags through git tag repointing. This replaced the legitimate entry point script with a malicious, multi-stage credential stealer. The malicious code was designed to execute silently before the legitimate Trivy scanner, making the compromise difficult to detect. Aqua Security confirmed the compromise of the Trivy GitHub Action script, setup script, and binary, and has removed all malicious artifacts. This attack highlights the risks associated with trusting third-party components in CI/CD pipelines, emphasizing the need for robust integrity checks and monitoring.

## Attack Chain

1. The attacker compromised the aquasecurity/trivy-action GitHub repository and maliciously modified the release tags via git tag repointing.
2. The legitimate entrypoint.sh script was replaced with a malicious version containing approximately 105 lines of added attack code.
3. When a CI/CD pipeline references the compromised action (e.g., aquasecurity/trivy-action@0.24.0), the runner downloads and executes the malicious entrypoint.sh.
4. The malicious script enumerates process IDs (PIDs) running on the runner to identify potential targets for credential theft.
5. The script executes a multi-stage credential theft operation targeting secrets, API keys, deploy tokens, and cloud credentials.
6. After credential theft, the legitimate Trivy scanner logic is executed, ensuring the workflow completes normally and avoiding immediate detection.
7. Stolen credentials and secrets are exfiltrated to an attacker-controlled server (details of exfiltration are not provided in the source).
8. The attacker gains unauthorized access to internal infrastructure, cloud resources, and other systems accessible with the stolen credentials.

## Impact

The compromise of the aquasecurity/trivy-action GitHub Action allowed attackers to steal credentials and secrets from affected CI/CD pipelines. While the exact number of victims is unknown, the widespread use of this action suggests a potentially large impact. Successful attacks could lead to unauthorized access to sensitive data, compromised infrastructure, and supply chain contamination. The silent nature of the attack makes detection challenging, increasing the window of opportunity for attackers to exploit stolen credentials.

## Recommendation

*   Monitor process execution on GitHub Actions runners for unexpected or suspicious scripts, specifically bash scripts (entrypoint.sh) executing from the `_work/_actions/aquasecurity/trivy-action` directory. Deploy the provided Sigma rule to identify such activity.
*   Implement integrity checks for third-party GitHub Actions used in CI/CD pipelines. Consider using commit SHA instead of tags to ensure immutability, mitigating the risk of git tag repointing.
*   Enable detailed logging on GitHub Actions runners, including process creation, network connections, and file system modifications, to enhance visibility into potentially malicious activity.
*   Rotate any credentials or secrets that were potentially exposed in CI/CD pipelines using the compromised trivy-action.
