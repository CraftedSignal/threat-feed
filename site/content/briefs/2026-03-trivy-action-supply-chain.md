---
title: Compromised aquasecurity/trivy-action GitHub Action
slug: 2026-03-trivy-action-supply-chain
description: Attackers poisoned 76 of 77 release tags of the aquasecurity/trivy-action GitHub Action by repointing them to malicious commits containing a multi-stage credential stealer that exfiltrates secrets, credentials, and allows undetected access to infrastructure in CI/CD pipelines.
date: "2026-03-30T21:48:14Z"
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
  - title: Detect Suspicious Trivy Action Entrypoint Modification
    description: Detects modifications to the trivy-action entrypoint.sh script, indicating a potential supply chain compromise.
    platform: sigma
    severity: high
    tactics:
      - supply_chain
    techniques:
      - T1195
    data_sources:
      - file_event
      - linux
  - title: Detect Script Execution in GitHub Actions Temp Directory
    description: Detects execution of shell scripts from the GitHub Actions temporary directory, which could indicate malicious activity.
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

On March 19, 2026, CrowdStrike's Engineering team identified a supply chain attack targeting the aquasecurity/trivy-action GitHub Action, a widely used open-source vulnerability scanner in CI/CD pipelines. The attackers retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits. This meant that any CI/CD pipeline using the compromised action would unknowingly execute malicious code before the legitimate Trivy scanner. This malicious code consisted of a multi-stage credential stealer, designed to harvest secrets and credentials available to the GitHub Actions runner. Aqua Security has confirmed the compromise and removed the malicious artifacts. The scope of the attack targeted any organization using the compromised versions of the trivy-action in their GitHub workflows, potentially granting the attacker access to sensitive data and internal infrastructure.

## Attack Chain

1.  The attacker compromised the aquasecurity/trivy-action GitHub repository, likely through compromised credentials or other means.
2.  The attacker repointed 76 of the 77 release tags (e.g., 0.24.0) to malicious commits, replacing the original action code with their own.
3.  A developer pushes code, opens a pull request, or merges a branch, triggering a GitHub Actions workflow that includes the compromised trivy-action.
4.  The GitHub Actions runner downloads the action specified by the tag (e.g., aquasecurity/trivy-action@0.24.0) from GitHub.
5.  The runner executes the malicious `entrypoint.sh` script, which prepends approximately 105 lines of attack code before executing the legitimate Trivy scanner logic.
6.  The malicious code enumerates process IDs (PIDs) to perform credential theft.
7.  The malicious code attempts to steal secrets and credentials available to the runner, including API keys, deploy tokens, and cloud credentials.
8.  The legitimate Trivy scanner runs after the malicious code, masking the compromise and allowing the workflow to complete normally. The stolen credentials are then exfiltrated.

## Impact

The compromise of the aquasecurity/trivy-action GitHub Action allowed attackers to potentially access secrets, credentials, and internal infrastructure across multiple organizations using the compromised action. The impact includes unauthorized access to cloud resources, code repositories, and other sensitive systems, leading to data breaches, service disruption, and reputational damage. While the exact number of victims is not specified, the widespread adoption of trivy-action suggests the potential for a large-scale impact across various sectors.

## Recommendation

*   Pin GitHub Actions to specific commit SHAs instead of tags to prevent tag repointing attacks. This ensures that the workflow always uses the intended version of the action.
*   Monitor GitHub Actions runner logs for suspicious script execution, especially within the `entrypoint.sh` of third-party actions. This helps detect malicious code injected into seemingly benign actions. Enable process creation logging on runners to assist with investigations.
*   Implement strong access controls and multi-factor authentication for GitHub accounts to prevent unauthorized modifications to repositories and actions. This reduces the risk of initial compromise.
*   Deploy the Sigma rule "Detect Suspicious Trivy Action Entrypoint Modification" to identify potential modifications to the trivy-action entrypoint script.
