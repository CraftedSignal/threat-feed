---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-03-trivy-action-compromise
description: The trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines, was compromised via git tag repointing to inject a multi-stage credential stealer.
date: "2026-03-30T07:13:10Z"
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
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Execution of trivy-action entrypoint.sh
    description: Detects execution of the entrypoint.sh script from the trivy-action GitHub Action, which could indicate malicious activity if the action is compromised.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Runner Process Discovery
    description: Detects the enumeration of process IDs (PIDs), which is the initial stage in the malicious campaign.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1057
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike detected suspicious script execution activity originating from GitHub Actions runners across multiple customer environments. Investigation revealed that the aquasecurity/trivy-action GitHub Action, a widely used open-source vulnerability scanner within CI/CD pipelines, had been compromised. Further analysis showed that 76 out of 77 release tags for the action were retroactively poisoned through git tag repointing. This injected malicious code into the action's entrypoint, allowing attackers to execute a multi-stage credential theft operation before the legitimate scanner ran, masking the malicious activity. Aqua Security has confirmed the compromise and removed the malicious artifacts. This supply chain attack highlights the risk of using mutable tags in GitHub Actions and the potential for attackers to gain access to sensitive credentials and infrastructure.

## Attack Chain

1.  Attacker compromises the aquasecurity/trivy-action GitHub repository or gains control over the release process.
2.  The attacker repoints existing git tags (e.g., 0.24.0) to malicious commits.
3.  A developer's CI/CD pipeline references the compromised trivy-action using a tag (e.g., uses: aquasecurity/trivy-action@0.24.0).
4.  When the workflow runs, the GitHub Actions runner downloads the compromised action from GitHub.
5.  The runner executes the malicious entrypoint.sh script, which initiates a multi-stage credential theft operation. This involves enumeration of process IDs (PIDs).
6.  The malicious script steals credentials from the runner's environment, secrets, and potentially the network.
7.  The script then executes the legitimate Trivy scanner to avoid raising suspicion.
8.  Stolen credentials are used to access internal infrastructure or cloud resources.

## Impact

The compromise of the trivy-action GitHub Action could have affected numerous organizations using the scanner in their CI/CD pipelines. Successful exploitation could result in the theft of sensitive credentials, including API keys, deploy tokens, and cloud credentials. This, in turn, may allow attackers to gain unauthorized access to internal infrastructure, deploy malicious code, or exfiltrate sensitive data. The exact number of affected organizations remains unclear, but the widespread use of trivy-action suggests a potentially significant impact.

## Recommendation

*   Pin GitHub Actions to specific, immutable commit SHAs instead of using mutable tags. This prevents attackers from repointing tags to malicious code ([https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/)).
*   Implement integrity monitoring on GitHub Actions runners to detect unexpected script executions or modifications to action code. Use `category: process_creation` and `product: linux` to monitor the `entrypoint.sh` file, and deploy the Sigma rule provided below.
*   Audit GitHub Action workflows for usage of aquasecurity/trivy-action and investigate any suspicious activity around the time of the compromise (March 2026).
