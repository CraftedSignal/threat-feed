---
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-04-trivy-action-supply-chain
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, injecting malicious code into the entrypoint.sh script to steal credentials from CI/CD pipelines before executing the legitimate Trivy scanner.
date: "2026-03-31T07:24:09Z"
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
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.crowdstrike.com/en/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects execution of shell scripts within the GitHub Actions runner environment that may indicate malicious activity from compromised actions.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Processes Spawning from Trivy Action Directory
    description: Detects processes spawned from the Trivy Action directory, which can indicate malicious activity after a supply chain compromise.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1569.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, a spike in suspicious script executions on Linux GitHub Actions runners was observed across multiple CrowdStrike Falcon platform customers. The investigation traced the activity to a supply chain compromise within the widely-used aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines. Attackers retroactively poisoned 76 out of 77 release tags by repointing them to malicious commits. This allowed them to inject a multi-stage credential stealer into the action's `entrypoint.sh` script. The malicious code executes before the legitimate scanner, making the compromise less noticeable. Aqua Security confirmed the compromise of the Trivy GitHub Action script, setup script, and binary and has removed the malicious artifacts. This incident highlights the risks associated with trusting third-party actions in CI/CD pipelines and the potential for attackers to exploit tag mutability in Git.

## Attack Chain

1.  The attacker gains unauthorized write access to the `aquasecurity/trivy-action` GitHub repository.
2.  The attacker retroactively modifies existing Git tags (e.g., `0.24.0`) to point to a malicious commit.
3.  The malicious commit injects approximately 105 lines of malicious code into the `entrypoint.sh` script, prepended before the legitimate Trivy scanner logic.
4.  A GitHub Actions workflow includes a step using the compromised `aquasecurity/trivy-action` by referencing a poisoned tag (e.g., `- uses: aquasecurity/trivy-action@0.24.0`).
5.  When the workflow runs on a GitHub Actions runner, the runner downloads the compromised action and executes the malicious `entrypoint.sh` script.
6.  The malicious code in `entrypoint.sh` enumerates running processes to identify potential credential sources and exfiltrates sensitive data.
7.  The legitimate Trivy scanner executes, masking the malicious activity.
8.  The attacker gains access to stolen credentials, secrets, and API keys, potentially allowing them to compromise cloud infrastructure, internal systems, and source code repositories.

## Impact

This supply chain attack directly impacted organizations using the compromised `aquasecurity/trivy-action` GitHub Action in their CI/CD pipelines. The number of affected organizations is currently unknown, but given the action's popularity, it is likely significant. Successful exploitation allows attackers to steal sensitive credentials, including API keys, cloud credentials, and deploy tokens. This can lead to unauthorized access to internal infrastructure, data exfiltration, and further compromise of the software supply chain. The incident highlights the critical importance of verifying the integrity of third-party dependencies and implementing robust security measures in CI/CD environments.

## Recommendation

*   Immediately audit your GitHub Actions workflows for usage of the `aquasecurity/trivy-action` and update to a safe version (as provided by Aqua Security) or remove the action entirely.
*   Implement integrity checks for third-party GitHub Actions by verifying the commit SHA instead of relying solely on tags to mitigate tag re-pointing attacks.
*   Monitor process execution on GitHub Actions runners for suspicious scripts, especially those running from within action directories, using process creation logs. An example detection rule is provided below.
*   Enable network connection logging on GitHub Actions runners to identify potential data exfiltration attempts originating from action scripts.
*   Review GitHub Actions logs for any anomalies or unexpected behavior that may indicate a compromise.
