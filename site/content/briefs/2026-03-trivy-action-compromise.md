---
title: Compromised trivy-action GitHub Action Steals Credentials
slug: 2026-03-trivy-action-compromise
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, where 76 of 77 release tags were retroactively poisoned with malicious code that executes a multi-stage credential theft operation.
date: "2026-03-30T06:19:01Z"
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
  - title: Detect Trivy Action Compromise - Suspicious Script Execution
    description: Detects execution of the malicious entrypoint.sh script associated with the compromised trivy-action GitHub Action.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - process_creation
      - linux
  - title: Detect Trivy Action Compromise - Runner Process Discovery
    description: Detects suspicious script execution indicative of the first stage of the compromised trivy-action GitHub Action, specifically process enumeration.
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

On March 19, 2026, CrowdStrike discovered a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines. The attack involved retroactively poisoning 76 of the 77 release tags via git tag repointing, replacing the legitimate entry point with a multi-stage credential stealer. The malicious code was designed to run silently before the real scanner, allowing workflows to complete normally and evade initial detection. Aqua Security has confirmed the compromise and removed the malicious artifacts. This incident highlights the risk associated with mutable tags in Git and the potential for supply chain attacks in CI/CD environments.

## Attack Chain

1. An attacker gains write access to the aquasecurity/trivy-action repository.
2. The attacker repoints existing git tags (e.g., `0.24.0`) to malicious commits.
3. A developer's CI/CD pipeline references the compromised trivy-action via a poisoned tag.
4. The GitHub Actions runner downloads the malicious action from GitHub and extracts it.
5. The runner executes the malicious `entrypoint.sh` script, which begins with credential-stealing code.
6. The malicious script enumerates process IDs (PIDs).
7. The script proceeds with multi-stage credential theft.
8. The script executes the legitimate Trivy scanner to mask malicious activity.

## Impact

The compromise of the aquasecurity/trivy-action GitHub Action potentially impacted numerous organizations using the scanner in their CI/CD pipelines. Successful exploitation results in the theft of secrets, API keys, deploy tokens, cloud credentials, and other sensitive information stored within the GitHub Actions runner environment. This stolen information could be used for unauthorized access to internal infrastructure, data exfiltration, or further malicious activities. The exact number of affected organizations remains unknown.

## Recommendation

*   Deploy the Sigma rule "Detect Trivy Action Compromise - Suspicious Script Execution" to detect malicious script execution within the GitHub Actions runner environment.
*   Review CI/CD pipeline configurations to identify and audit usage of the `aquasecurity/trivy-action`.
*   Monitor process execution on GitHub Actions runners for unusual or unexpected activity.
*   Implement stricter controls on write access to GitHub repositories and actions to prevent future compromises.
