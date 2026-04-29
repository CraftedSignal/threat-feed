---
title: Compromised trivy-action GitHub Action
slug: 2026-03-trivy-action-compromise
description: The trivy-action GitHub Action was compromised via git tag repointing, with 76 of 77 release tags poisoned to include a multi-stage credential stealer that executes before the legitimate scanner, impacting CI/CD pipelines.
date: "2026-03-31T09:21:47Z"
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
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Suspicious Process Execution in GitHub Actions Runner
    description: Detects execution of suspicious processes within the GitHub Actions runner environment, potentially indicating malicious activity injected via a compromised action.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of GitHub Action Entrypoint
    description: Detects modification of the entrypoint.sh file within a GitHub Action directory, which could indicate a supply chain compromise.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1199
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On March 19, 2026, a spike in script execution detections on Linux GitHub Actions runners led to the discovery of a supply chain compromise targeting the aquasecurity/trivy-action GitHub Action. The attack involved retroactively poisoning 76 of the 77 release tags by repointing them to malicious commits. This injected a multi-stage credential stealer into the action's entrypoint.sh script. The malicious code executes before the legitimate Trivy scanner, allowing it to steal credentials and secrets from the runner environment without disrupting normal workflow execution. Aqua Security has removed all malicious artifacts, but pipelines that previously used the compromised action may have been affected, potentially leaking sensitive information. This incident highlights the risks associated with mutable tags in Git-based CI/CD systems.

## Attack Chain

1.  Attacker gains write access to the `aquasecurity/trivy-action` GitHub repository.
2.  Attacker retroactively modifies existing release tags (e.g., `0.24.0`) to point to malicious commits.
3.  The malicious commit prepends approximately 105 lines of code to the `entrypoint.sh` script, injecting a credential stealer.
4.  When a CI/CD pipeline uses the compromised action (e.g., `uses: aquasecurity/trivy-action@0.24.0`), the GitHub Actions runner downloads and executes the malicious `entrypoint.sh`.
5.  The malicious script enumerates running processes on the runner.
6.  The injected script steals credentials, API keys, and other secrets available in the runner's environment.
7.  After stealing credentials, the script executes the legitimate Trivy scanner to avoid suspicion.
8.  Stolen credentials are used to access internal infrastructure and resources, leading to data exfiltration or further compromise.

## Impact

The compromise of the `trivy-action` GitHub Action could have affected numerous organizations using it in their CI/CD pipelines. With 76 of 77 release tags poisoned, the potential for widespread credential theft is significant. Successful attacks could allow unauthorized access to source code repositories, cloud infrastructure, and other sensitive systems. The number of affected organizations is currently unknown, but the wide adoption of `trivy-action` suggests a potentially large impact.

## Recommendation

*   Review CI/CD pipeline configurations for usage of the `aquasecurity/trivy-action` and update to a safe version or a different vulnerability scanner.
*   Monitor GitHub Actions runner logs for suspicious script execution, especially involving `entrypoint.sh` in the `aquasecurity/trivy-action` directory.
*   Implement the provided Sigma rule to detect execution of suspicious processes from within the GitHub Actions runner environment.
*   Audit GitHub repositories for unexpected changes to tags and commit history.
*   Rotate any potentially compromised credentials, API keys, and secrets that may have been accessible to the GitHub Actions runners.
