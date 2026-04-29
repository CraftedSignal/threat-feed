---
title: Compromised trivy-action GitHub Action Steals Credentials
slug: 2026-03-trivy-supply-chain
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, injecting a multi-stage credential stealer into CI/CD pipelines, affecting 76 of 77 release tags.
date: "2026-03-28T09:15:08Z"
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
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects potentially malicious shell scripts executed within a GitHub Actions runner environment, indicating a possible compromise of a GitHub Action.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - process_creation
      - linux
  - title: Detect Process ID Enumeration via ps Command
    description: Detects the use of 'ps' command combined with other utilities to enumerate process IDs, which is the first stage shown in the compromise.
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

On March 19, 2026, CrowdStrike's engineering team discovered a supply chain attack targeting the widely-used aquasecurity/trivy-action GitHub Action. This action is a popular open-source vulnerability scanner commonly used in CI/CD pipelines. The attackers compromised the action by retroactively poisoning 76 of the 77 release tags via git tag repointing. This involved replacing the legitimate action's entry point with a malicious multi-stage credential stealer. The malicious code executes before the actual Trivy scanner, allowing it to operate silently and steal credentials without disrupting the normal workflow execution. Aqua Security has confirmed the compromise and removed the malicious artifacts.

## Attack Chain

1.  **Compromise:** Attackers gained write access and repointed git tags on the `aquasecurity/trivy-action` repository, injecting malicious code into the action's entrypoint.sh.
2.  **Delivery:** CI/CD pipelines referencing the compromised action (e.g., `aquasecurity/trivy-action@0.24.0`) automatically downloaded and executed the malicious code during workflow runs.
3.  **Execution (Stage 1):** The malicious `entrypoint.sh` script executed before the legitimate Trivy scanner, initiating a credential theft operation.  The script begins by enumerating process IDs (PIDs).
4.  **Credential Theft (Multi-Stage):** The compromised script performed a multi-stage credential theft operation (details of stages 2+ are not provided).
5.  **Scanner Execution:** After the credential theft stages, the script executed the legitimate Trivy scanner to mask the malicious activity.
6.  **Exfiltration:** (Exfiltration details are not provided).
7.  **Persistence:** (Persistence mechanisms are not provided).
8.  **Objective:** The attacker's primary objective was to steal credentials from CI/CD pipelines, granting them unauthorized access to sensitive resources and infrastructure.

## Impact

The compromise of the trivy-action GitHub Action had the potential to impact numerous organizations using the action in their CI/CD pipelines. Successful credential theft could lead to unauthorized access to cloud resources, code repositories, and other sensitive systems. The exact number of affected organizations and the extent of the damage are not specified in the source document.

## Recommendation

*   Enable process creation logging on CI/CD runner environments to provide visibility into unexpected script execution, as described in the initial discovery section.
*   Deploy the Sigma rule "Detect Suspicious Script Execution in GitHub Actions Runner" to identify potentially malicious scripts running within GitHub Actions runners.
*   Monitor network connections originating from CI/CD runner processes for unusual or unauthorized destinations, although specific C2 domains are not provided in the source material.
