---
title: Compromised trivy-action GitHub Action Enables Credential Theft
slug: 2026-03-trivy-action-compromise
description: The trivy-action GitHub Action was compromised via git tag repointing, with attackers poisoning 76 of 77 release tags to inject a multi-stage credential stealer before the legitimate scanner runs, granting attackers access to CI/CD pipeline secrets.
date: "2026-03-28T08:12:22Z"
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
    description: Detects execution of potentially malicious scripts within GitHub Actions runners, indicating a possible compromise or unauthorized activity.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Runner Process Discovery
    description: Detects enumeration of process IDs (PIDs), which is used for runner process discovery and is part of the credential theft operation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, a spike in script execution detections on Linux-based GitHub Actions runners led to the discovery of a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action. The attackers retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits. This manipulation replaced the legitimate entry point with a multi-stage credential stealer. The malicious code operates silently before the legitimate Trivy scanner logic is executed, which allows the malicious activity to remain hidden as workflows appear to complete normally. Aqua Security has confirmed the compromise and removed the malicious artifacts. This incident highlights the risks associated with trusting third-party actions in CI/CD pipelines and the potential for attackers to gain access to sensitive credentials and internal infrastructure.

## Attack Chain

1. A developer triggers a GitHub Actions workflow that utilizes the `aquasecurity/trivy-action`.
2. The GitHub Actions runner downloads the specified version of the `trivy-action` from GitHub.
3. Due to tag repointing, the downloaded action contains malicious code in the `entrypoint.sh` script.
4. The malicious `entrypoint.sh` script executes a multi-stage credential theft operation.
5. The script enumerates process IDs (PIDs) to discover runner processes.
6. After credential theft, the legitimate Trivy scanner logic is executed to maintain the appearance of normal operation.
7. Stolen credentials and secrets are likely exfiltrated to a attacker controlled server.
8. The attacker uses the stolen credentials to gain unauthorized access to internal infrastructure, cloud resources, or other sensitive systems.

## Impact

The compromise of the trivy-action GitHub Action could have resulted in widespread credential theft across numerous organizations using the affected versions. With 76 of 77 release tags poisoned, a vast majority of users were exposed. Successful credential theft can lead to unauthorized access to sensitive systems, data breaches, and potential supply chain attacks affecting downstream customers. The incident highlights the critical importance of supply chain security and the need for robust monitoring and detection mechanisms in CI/CD pipelines.

## Recommendation

*   Inspect your CI/CD pipelines for usage of the `aquasecurity/trivy-action` GitHub Action and verify the integrity of the action being used.
*   Implement the Sigma rule `Detect Suspicious Script Execution in GitHub Actions Runner` to identify potentially malicious script execution within GitHub Actions runners.
*   Monitor process execution within GitHub Actions runners for unusual or unexpected activity that deviates from normal CI/CD operations (reference: Attack Chain step 5).
*   Enable detailed logging on GitHub Actions runners to capture process execution, network connections, and file system activity for forensic analysis and threat hunting.
*   Implement strong access controls and least privilege principles for GitHub Actions secrets and credentials to limit the impact of potential credential theft.
