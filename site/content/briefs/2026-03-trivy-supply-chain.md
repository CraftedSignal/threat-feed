---
title: 'Compromised trivy-action GitHub Action: Supply Chain Credential Theft'
slug: 2026-03-trivy-supply-chain
description: A supply chain attack compromised the trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines, with the attacker retroactively poisoning 76 of 77 release tags to steal credentials.
date: "2026-03-30T06:30:00Z"
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
  - title: Suspicious GitHub Actions Runner Script Execution
    description: Detects potentially malicious script execution within GitHub Actions runner environments by monitoring for unusual parent-child process relationships.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1053.005
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Trivy Action Entrypoint Modification Detection
    description: Detects modifications to the entrypoint.sh script within the trivy-action GitHub Action directory, which could indicate a supply chain compromise.
    platform: sigma
    severity: medium
    tactics:
      - supply_chain
    techniques:
      - T1195
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike discovered a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action, a widely used open-source vulnerability scanner in CI/CD pipelines. The attacker retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits. This replaced the legitimate action entry point with a multi-stage credential stealer. The malicious code executes before the real Trivy scanner, allowing it to operate undetected while exfiltrating sensitive information. Aqua Security confirmed the compromise and removed malicious artifacts. This attack highlights the risks associated with trusting third-party actions in CI/CD pipelines and the potential for silent code modification via Git tag manipulation.

## Attack Chain

1. **Initial Compromise:** The attacker gains write access to the aquasecurity/trivy-action repository.
2. **Tag Repointing:** The attacker modifies existing Git tags (e.g., 0.24.0) to point to malicious commits without altering the tag name or timestamps.
3. **Malicious Code Injection:** The malicious commit prepends approximately 105 lines of attack code to the entrypoint.sh script of the trivy-action.
4. **Runner Process Discovery:** The injected code enumerates process IDs (PIDs) running on the GitHub Actions runner.
5. **Credential Theft:** The malicious script executes multi-stage credential theft operations.
6. **Silent Execution:** The original Trivy scanner is executed after the malicious code, masking the compromise and ensuring the CI/CD pipeline completes as expected.
7. **Data Exfiltration:** Stolen credentials and secrets are exfiltrated to an attacker-controlled server.
8. **Persistence:** The attacker could potentially use the stolen credentials to further compromise internal infrastructure or cloud environments.

## Impact

This supply chain attack could have affected a large number of organizations using the trivy-action GitHub Action in their CI/CD pipelines. Successful exploitation could lead to the theft of sensitive credentials, including API keys, deploy tokens, and cloud credentials, potentially resulting in unauthorized access to internal infrastructure and cloud resources. The impact is amplified by the silent nature of the attack, making it difficult for organizations to detect and respond to the compromise.

## Recommendation

*   Deploy the Sigma rule below to detect suspicious script execution within GitHub Actions runner environments based on parent-child process relationships (`rules[0]`).
*   Enable detailed process creation logging on GitHub Actions runners, focusing on the `entrypoint.sh` script execution to increase visibility into potentially malicious activities (`rules[0]`, `rules[1]`).
*   Implement integrity checks for third-party GitHub Actions by verifying the SHA256 hash of the action code before execution.
*   Review CI/CD pipeline configurations for use of the compromised trivy-action (`aquasecurity/trivy-action`) and update to a verified safe version.
