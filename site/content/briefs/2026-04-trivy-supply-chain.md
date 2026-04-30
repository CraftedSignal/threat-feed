---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-04-trivy-supply-chain
description: The trivy-action GitHub Action was compromised via git tag repointing, where 76 of 77 release tags were retroactively poisoned, leading to a multi-stage credential theft operation discovered following a spike in script execution detections on Linux runners.
date: "2026-03-31T08:36:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1133
    technique_name: External Service Instance Hijacking
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects potentially malicious script execution within GitHub Actions runner environments, indicating a possible compromise.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Runner.Worker Process Spawning Shell
    description: Detects Runner.Worker process spawning a shell which is an indicator of command execution within a Github Actions runner.
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

On March 19, 2026, CrowdStrike detected a spike in script execution on Linux-based GitHub Actions runners. Investigation traced the activity to a compromise of the aquasecurity/trivy-action GitHub Action, a widely used open-source vulnerability scanner in CI/CD pipelines. The compromise involved retroactively poisoning 76 of the scanner's 77 release tags through git tag repointing. This replaced the legitimate entry point with a multi-stage credential stealer. The malicious code ran before the actual scanner, making the compromise difficult to detect as workflows appeared to complete normally. Aqua Security confirmed the compromise of the Trivy GitHub Action script, setup script, and binary, and removed the malicious artifacts. This supply chain attack highlights the risk of relying on third-party actions in CI/CD pipelines without proper verification and monitoring.

## Attack Chain

1. A developer pushes code, opens a pull request, or merges a branch in a repository using the compromised trivy-action.
2. The GitHub Actions runner executes the workflow, downloading the specified version of the trivy-action. Due to tag repointing, a malicious version of the action is downloaded instead of the legitimate one.
3. The malicious `entrypoint.sh` script is executed, which prepends approximately 105 lines of attack code before the original Trivy scanner logic.
4. The malicious script enumerates process IDs (PIDs) on the runner to identify potential targets.
5. The script executes a multi-stage credential theft operation, stealing secrets and credentials available within the runner environment.
6. The legitimate Trivy scanner is executed after the malicious code, masking the compromise as the workflow appears to complete successfully.
7. Stolen credentials are exfiltrated to a destination controlled by the attacker.
8. The attacker uses the stolen credentials to gain unauthorized access to internal infrastructure, cloud resources, or other sensitive systems.

## Impact

This supply chain compromise affected users of the aquasecurity/trivy-action GitHub Action. The retroactive poisoning of 76 release tags meant that any CI/CD pipeline using those versions of the action was potentially compromised. The impact included the potential theft of sensitive credentials, secrets, and API keys stored within the GitHub Actions runner environment. Successful credential theft could lead to unauthorized access to critical infrastructure, data breaches, and further downstream attacks. The number of affected organizations is unknown, but given the popularity of trivy-action, the scope could be significant.

## Recommendation

*   Review your GitHub Actions workflows for usage of `aquasecurity/trivy-action` and verify the integrity of the action's code. Consider pinning to specific commit SHAs instead of tags to avoid tag repointing attacks.
*   Deploy the Sigma rule `Detect Suspicious Script Execution in GitHub Actions Runner` to identify potentially malicious script execution within GitHub Actions runner environments.
*   Monitor process execution on GitHub Actions runners for unusual or unexpected activity, particularly scripts running from temporary directories, to detect deviations from expected CI/CD behavior.
*   Implement strict access controls and credential management policies for GitHub Actions secrets and credentials to minimize the impact of potential credential theft.
