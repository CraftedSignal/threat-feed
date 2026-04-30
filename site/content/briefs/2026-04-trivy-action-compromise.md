---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-04-trivy-action-compromise
description: The trivy-action GitHub Action, a widely used vulnerability scanner in CI/CD pipelines, was compromised via git tag repointing to inject a multi-stage credential stealer, affecting 76 of 77 release tags.
date: "2026-03-31T06:07:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - github-actions
  - credential-theft
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Process Enumeration on GitHub Actions Runner
    description: Detects potential credential theft activity by monitoring for process enumeration commands commonly used by attackers after compromising a CI/CD runner
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious Entrypoint Script Execution in trivy-action
    description: Detects execution of the compromised entrypoint.sh script within the trivy-action GitHub Action.
    platform: sigma
    severity: high
    tactics:
      - supply_chain
    techniques:
      - T1199
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike detected a spike in suspicious script executions on Linux-based GitHub Actions runners, which led to the discovery of a supply chain compromise affecting the `aquasecurity/trivy-action` GitHub Action. This action is a popular open-source vulnerability scanner frequently used in CI/CD pipelines. The attacker retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits. These commits replaced the legitimate entry point with a multi-stage credential stealer. The injected code executes before the original scanner, allowing workflows to complete seemingly normally while secretly exfiltrating sensitive information. Aqua Security has confirmed and removed the malicious artifacts. This incident highlights the risks associated with mutable tags in Git-based workflows and the importance of verifying action integrity.

## Attack Chain

1.  Attacker gains write access to the `aquasecurity/trivy-action` repository on GitHub.
2.  The attacker modifies the action's `entrypoint.sh` script to include malicious code for credential theft. Specifically, the attacker prepends approximately 105 lines of malicious code.
3.  The attacker uses git tag repointing to retroactively poison existing release tags (e.g., `@0.24.0`) to point to the malicious commit.
4.  Developers' CI/CD pipelines reference the compromised `trivy-action` using a poisoned tag (e.g., `aquasecurity/trivy-action@0.24.0`).
5.  When a workflow runs, the GitHub Actions runner downloads and executes the malicious `entrypoint.sh` script, granting it access to the runner's environment, secrets, and network.
6.  The malicious script enumerates running processes to identify potential targets for credential theft.
7.  The malicious code exfiltrates credentials and secrets.
8.  The original `trivy` scanner is executed, masking the malicious activity and allowing the workflow to complete normally.

## Impact

The compromise of the `trivy-action` GitHub Action allowed attackers to steal credentials and secrets from CI/CD pipelines that used the compromised action. Because the malicious code ran with the full privileges of the runner, it had access to sensitive information such as API keys, deployment tokens, and cloud credentials. The number of affected organizations is unknown, but given the widespread adoption of `trivy-action`, the potential impact is significant. Successful exploitation can lead to unauthorized access to cloud resources, code repositories, and other sensitive systems.

## Recommendation

*   Inspect your CI/CD pipeline configurations for usage of the `aquasecurity/trivy-action` and audit the integrity of the referenced tags against the known good commits, if available from Aqua Security's advisories.
*   Implement tooling and processes to verify the integrity of third-party GitHub Actions used in CI/CD pipelines.
*   Monitor process execution on GitHub Actions runners for suspicious activity, such as enumeration of processes or unexpected network connections (see Sigma rule below).
*   Enable and review process creation logs on CI/CD runner environments to identify anomalous script execution (see Sigma rule below).
