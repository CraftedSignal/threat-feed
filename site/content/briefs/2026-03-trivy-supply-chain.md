---
title: Compromised trivy-action GitHub Action for Credential Theft
slug: 2026-03-trivy-supply-chain
description: A supply chain compromise of the aquasecurity/trivy-action GitHub Action resulted in the insertion of malicious code into 76 out of 77 release tags, silently performing credential theft operations on Linux runners before running the legitimate Trivy scanner.
date: "2026-03-30T22:05:09Z"
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

On March 19, 2026, CrowdStrike's Engineering team detected a spike in script execution on Linux GitHub Actions runners, tracing the activity to a compromised GitHub Action named aquasecurity/trivy-action. This popular open-source vulnerability scanner used in CI/CD pipelines had 76 of its 77 release tags retroactively poisoned via git tag repointing. This replaced the legitimate entry point with a multi-stage credential stealer that ran silently before the real scanner. Aqua Security has confirmed the compromise of the Trivy GitHub Action script, setup script, and binary, and has removed the malicious artifacts. The malicious code prepends approximately 105 lines of attack code before the legitimate Trivy scanner logic. This supply chain attack highlights the risks associated with trusting third-party components in CI/CD pipelines and the importance of verifying the integrity of dependencies.

## Attack Chain

1. An attacker compromises the aquasecurity/trivy-action GitHub Action by repointing git tags.
2. Developers unknowingly pull the compromised action into their CI/CD workflows by referencing a poisoned tag (e.g., `@0.24.0`).
3. When a workflow runs, the runner downloads and extracts the malicious action from GitHub.
4. The runner executes the modified `entrypoint.sh`, which now contains malicious code.
5. The malicious code enumerates process IDs (PIDs) running on the runner.
6. The malicious code then executes multi-stage credential theft operations on the runner, targeting environment variables, files, and other secrets.
7. After the credential theft, the legitimate Trivy scanner is executed to mask the malicious activity.
8. The workflow completes, seemingly successfully, while the stolen credentials are used for unauthorized access to resources.

## Impact

This supply chain attack compromised 76 out of 77 release tags of a widely used GitHub Action, potentially impacting thousands of organizations that rely on it for vulnerability scanning in their CI/CD pipelines. Successful exploitation leads to the theft of sensitive credentials, including API keys, deploy tokens, and cloud credentials. These stolen credentials can be used to gain unauthorized access to internal infrastructure, cloud resources, and source code repositories, leading to data breaches, code tampering, and service disruptions.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious Process Enumeration in GitHub Actions" to your SIEM and tune for your environment to detect unusual process enumeration on GitHub Actions runners.
*   Deploy the Sigma rule "Detect Malicious Trivy Action Entrypoint" to identify instances where the `entrypoint.sh` script of the aquasecurity/trivy-action is modified with malicious code.
*   Pin specific, verified commits of GitHub Actions instead of using mutable tags to avoid tag repointing attacks.
*   Implement strong secret management practices, such as using dedicated secret stores and regularly rotating credentials.
