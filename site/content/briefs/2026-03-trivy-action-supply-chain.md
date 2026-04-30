---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-03-trivy-action-supply-chain
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, injecting a multi-stage credential stealer into CI/CD pipelines, allowing for the theft of secrets and credentials.
date: "2026-03-30T06:24:43Z"
type: advisory
types:
  - advisory
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
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects suspicious bash scripts being executed within the GitHub Actions runner environment, potentially indicating malicious activity injected through a compromised action.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Trivy Action Entrypoint Modification
    description: Detects modifications to the entrypoint.sh script within the aquasecurity/trivy-action directory, indicating potential tampering or malicious code injection.
    platform: sigma
    severity: medium
    tactics:
      - integrity
    techniques:
      - T1588.002
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike's Engineering team discovered a supply chain compromise targeting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines. The attackers retroactively poisoned 76 of the scanner’s 77 release tags using git tag repointing, replacing the original entry point with a multi-stage credential stealer. The malicious code operates before the legitimate scanner, masking its activity and allowing workflows to appear normal. This attack highlights the risks associated with mutable tags in Git and the potential for widespread compromise when relying on third-party actions within CI/CD environments. Defenders should implement strong integrity checks and consider using immutable references to mitigate such risks.

## Attack Chain

1. An attacker gains write access to the aquasecurity/trivy-action repository.
2. The attacker uses git tag repointing to modify existing release tags (e.g., 0.24.0), replacing the legitimate entrypoint.sh script with a malicious version.
3. A developer's CI/CD pipeline includes a step that uses the compromised trivy-action by referencing a poisoned tag (e.g., uses: aquasecurity/trivy-action@0.24.0).
4. When the workflow runs on a GitHub Actions runner, the runner downloads the compromised action and executes the malicious entrypoint.sh script.
5. The malicious script enumerates running processes to identify potential credential sources.
6. The script steals credentials and secrets from the runner's environment, including API keys, deployment tokens, and cloud credentials.
7. After stealing credentials, the malicious script executes the legitimate Trivy scanner to avoid raising suspicion.
8. The stolen credentials are used to gain unauthorized access to internal infrastructure and resources.

## Impact

The compromise of the trivy-action GitHub Action could impact a significant number of organizations relying on this popular scanner in their CI/CD pipelines. With 76 of 77 release tags poisoned, the potential scope of the attack is broad. Successful exploitation leads to the theft of sensitive credentials, enabling attackers to access internal infrastructure, deploy malicious code, or exfiltrate sensitive data. The silent nature of the attack, with the legitimate scanner still running, makes detection challenging and increases the dwell time of the attacker.

## Recommendation

*   Enable process monitoring on GitHub Actions runners to detect suspicious script execution and unusual process trees (reference: Attack Chain).
*   Implement integrity checks for third-party actions used in CI/CD pipelines to verify their authenticity and prevent tampering (reference: Overview).
*   Consider using immutable references (e.g., commit SHAs instead of tags) for GitHub Actions to prevent tag repointing attacks (reference: Overview).
*   Deploy the Sigma rule below to detect suspicious bash scripts executing in the context of GitHub Action runners (reference: rules).
