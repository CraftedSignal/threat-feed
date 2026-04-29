---
title: Compromised trivy-action GitHub Action Inserts Credential Stealer
slug: 2026-03-trivy-action-compromise
description: A supply chain compromise of the trivy-action GitHub Action resulted in the insertion of a multi-stage credential stealer into CI/CD pipelines, which executes before the legitimate Trivy scanner, silently stealing credentials while allowing the workflow to appear normal.
date: "2026-03-28T08:30:07Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
  - ci/cd
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Process from Trivy Action
    description: Detects suspicious processes spawned from the compromised trivy-action entrypoint.sh in GitHub Actions runners.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Github Actions Runner Enumerating Processes
    description: Detects the enumeration of processes which is the initial stage of the credential stealer.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, a spike in script execution detections on Linux platforms linked to GitHub Actions runners led to the discovery of a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action. The popular open-source vulnerability scanner, commonly used in CI/CD pipelines, was found to have 76 of its 77 release tags retroactively poisoned via git tag repointing. This replacement introduced a multi-stage credential stealer that silently executes before the legitimate Trivy scanner, thus workflows complete successfully. Aqua Security has confirmed the compromise of the Trivy GitHub Action script, setup script, and binary, and removed the malicious artifacts. The malicious `entrypoint.sh` script prepends approximately 105 lines of attack code before the legitimate scanner logic.

## Attack Chain

1.  An attacker compromises the aquasecurity/trivy-action GitHub Action by repointing git tags to malicious commits.
2.  A developer's CI/CD pipeline includes a step that uses the compromised trivy-action (e.g., `aquasecurity/trivy-action@0.24.0`).
3.  During the pipeline execution, the GitHub Actions runner downloads the malicious version of the action.
4.  The runner executes the `entrypoint.sh` script, which contains the prepended malicious code.
5.  The malicious code enumerates process IDs (PIDs).
6.  The `entrypoint.sh` executes a multi-stage credential theft operation.
7.  After stealing credentials, the script executes the legitimate Trivy scanner to avoid raising suspicion.
8.  Stolen credentials exfiltrated to attacker-controlled infrastructure (details not specified in source).

## Impact

This supply chain attack has the potential to impact numerous organizations that rely on the trivy-action GitHub Action in their CI/CD pipelines. Compromised pipelines can lead to the theft of sensitive credentials, including API keys, deploy tokens, and cloud credentials. Successful exploitation grants attackers unauthorized access to internal infrastructure, potentially leading to data breaches, service disruption, or further lateral movement within the victim's environment. The number of affected organizations and the full extent of the damage remain unknown.

## Recommendation

*   Inspect CI/CD pipeline logs for unexpected script executions within the `aquasecurity/trivy-action` directory, specifically `entrypoint.sh`, as described in the **Attack Chain**.
*   Implement integrity checks for GitHub Actions used in CI/CD pipelines to verify the authenticity and prevent tampering, mitigating future supply chain attacks.
*   Deploy the Sigma rule to detect suspicious processes spawned from the `entrypoint.sh` script of the `aquasecurity/trivy-action`.
*   Monitor network connections from GitHub Actions runners for unusual outbound traffic patterns that may indicate credential exfiltration.
*   Review and rotate any credentials that may have been exposed during the timeframe of the compromise, based on the **Overview** section.
