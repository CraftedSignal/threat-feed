---
title: Compromised trivy-action GitHub Action via Git Tag Repointing
slug: 2026-03-trivy-supply-chain
description: The trivy-action GitHub Action was compromised via git tag repointing, where 76 of 77 release tags were retroactively poisoned, replacing the legitimate entry point with a credential stealer that ran silently before the real scanner, targeting GitHub Actions runners on Linux.
date: "2026-03-28T08:17:27Z"
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
    technique_id: T1133
    technique_name: External Service
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects suspicious shell script execution within GitHub Actions runner environments, potentially indicating malicious activity originating from compromised actions.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Trivy Action Entrypoint Execution
    description: Detects execution of the trivy-action entrypoint.sh script, which may indicate a compromised action is being used.
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

On March 19, 2026, CrowdStrike observed a spike in script execution detections on Linux GitHub Actions runners, tracing the activity to a compromised GitHub Action named `aquasecurity/trivy-action`. This popular open-source vulnerability scanner is widely used in CI/CD pipelines. The investigation revealed that 76 of the scanner’s 77 release tags were retroactively poisoned through git tag repointing. This malicious modification replaced the legitimate entry point with a multi-stage credential stealer. The malicious code was designed to run silently before the legitimate scanner, ensuring that workflows appeared to complete normally. Aqua Security has confirmed the compromise of the Trivy GitHub Action script, setup script, and binary and removed the malicious artifacts.

## Attack Chain

1.  An attacker gains the ability to modify the `aquasecurity/trivy-action` GitHub repository, specifically the ability to repoint git tags.
2.  The attacker repoints existing tags (e.g., `0.24.0`) to malicious commits.
3.  When a GitHub Actions workflow uses the compromised `aquasecurity/trivy-action` (e.g., `uses: aquasecurity/trivy-action@0.24.0`), the runner downloads the malicious version of the action.
4.  The malicious `entrypoint.sh` script is executed within the GitHub Actions runner environment.
5.  The malicious script enumerates process IDs (PIDs) running on the runner to discover other processes and potentially extract credentials from their memory or environment variables.
6.  After the credential theft operation, the legitimate Trivy scanner is executed to maintain the appearance of normal operation.
7.  The stolen credentials could be used to access sensitive resources, such as cloud infrastructure, internal networks, or source code repositories.

## Impact

This supply chain compromise could affect any organization using the `aquasecurity/trivy-action` GitHub Action in their CI/CD pipelines. The successful execution of the malicious code leads to the theft of credentials stored within the GitHub Actions runner environment. Attackers can use stolen credentials to pivot into victim infrastructure, leading to data breaches, code compromise, or denial of service.

## Recommendation

*   Inspect GitHub Action workflows for usage of `aquasecurity/trivy-action` and consider using specific commit SHAs instead of mutable tags to ensure integrity.
*   Monitor process execution on GitHub Actions runners for unexpected script execution, as described in the "Initial Discovery" section, to identify potential compromises early.
*   Deploy the Sigma rule "Detect Suspicious Script Execution in GitHub Actions Runner" to your SIEM to identify potential malicious activity on GitHub Actions runners.
*   Review logs for any suspicious activity originating from GitHub Actions runners, as these may indicate successful credential theft.
