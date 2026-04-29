---
title: Compromised trivy-action GitHub Action Injects Credential Stealer
slug: 2026-03-trivy-action-compromise
description: The trivy-action GitHub Action was compromised via tag repointing, injecting a multi-stage credential stealer into CI/CD pipelines, affecting 76 of 77 release tags.
date: "2026-03-21T09:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects execution of shell scripts from unusual locations within the GitHub Actions runner environment, indicating potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Network Connection from GitHub Actions Runner to Public IP
    description: Detects network connections initiated from GitHub Actions runners to public IP addresses, which could indicate command and control or data exfiltration activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

On March 19, 2026, a spike in script execution detections on Linux platforms was observed across multiple CrowdStrike Falcon customers. Investigation revealed a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines. The attacker retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits, replacing the legitimate entry point with a multi-stage credential stealer. The malicious code executes before the real scanner, stealing credentials silently and allowing workflows to complete normally, masking the compromise. Aqua Security has confirmed the compromise and removed malicious artifacts. This incident highlights the risk of using mutable tags in GitHub Actions and the potential for attackers to steal secrets, credentials, and gain access to internal infrastructure.

## Attack Chain

1.  Attacker gains write access to the aquasecurity/trivy-action GitHub repository.
2.  The attacker retroactively repoints existing tags (e.g., 0.24.0) to malicious commits via `git tag` repointing.
3.  A developer's CI/CD pipeline references the compromised trivy-action using a tag (e.g., `aquasecurity/trivy-action@0.24.0`).
4.  During workflow execution, the GitHub Actions runner downloads the malicious code from the repointed tag.
5.  The malicious `entrypoint.sh` script executes before the legitimate Trivy scanner.
6.  The `entrypoint.sh` script enumerates process IDs (PIDs) to identify potential credential locations.
7.  The script executes a multi-stage credential theft operation, potentially targeting API keys, deploy tokens, and cloud credentials.
8.  After the credential theft, the legitimate Trivy scanner executes, allowing the workflow to complete normally and avoid immediate detection.

## Impact

The compromise of the trivy-action GitHub Action allows attackers to steal sensitive credentials from CI/CD pipelines. This could lead to unauthorized access to cloud environments, source code repositories, and other internal infrastructure. Due to the widespread use of trivy-action, a large number of organizations were potentially affected. Successful credential theft could enable data exfiltration, code modification, and deployment of malicious applications.

## Recommendation

*   Implement immutable references to GitHub Actions by using commit SHA instead of tags (reference: overview).
*   Monitor process execution on GitHub Actions runners for unexpected script execution using the `process_creation` Sigma rule below.
*   Enable detailed logging on GitHub Actions runners to capture command-line arguments and network connections (reference: `process_creation` and `network_connection` Sigma rules).
*   Audit CI/CD pipelines for usage of the `aquasecurity/trivy-action` and update to a verified, uncompromised version or a commit SHA (reference: overview).
*   Investigate any unusual activity originating from GitHub Actions runners between March 19, 2026, and March 20, 2026, as this is when the initial spike in malicious activity was observed (reference: overview).
