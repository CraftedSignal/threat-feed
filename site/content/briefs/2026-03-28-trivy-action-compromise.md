---
brief_id: brief-2026-03-28-trivy-action-compromise
event_id: brief-2026-03-28-trivy-action-compromise
revision: 2
activity_at: "2026-03-28T09:23:42Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:a5c285129a216315310d5de27cec4044fcb26069aea70ca7ad8f539f870d9b2a
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Compromised trivy-action GitHub Action Steals Credentials
slug: 2026-03-28-trivy-action-compromise
description: A supply chain compromise of the trivy-action GitHub Action resulted in the insertion of a multi-stage credential stealer into CI/CD pipelines, executing before the legitimate scanner to steal secrets from GitHub Actions runners.
date: "2026-03-28T09:23:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
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
  - title: Detect Suspicious Script Execution in GitHub Actions Runner
    description: Detects suspicious shell scripts executed within GitHub Actions runners, potentially indicating a compromised action.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Credential Theft via Process Enumeration in GitHub Actions
    description: Detects suspicious attempts to enumerate processes within a GitHub Actions runner, a common technique used by credential stealers.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1057
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, CrowdStrike discovered a supply chain attack targeting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines. Attackers retroactively poisoned 76 of the 77 release tags by repointing them to malicious commits. This injected a multi-stage credential stealer into any workflow using the compromised action. The malicious code was designed to execute silently before the legitimate Trivy scanner, allowing workflows to complete normally and evade initial detection. Aqua Security has confirmed the compromise and removed the malicious artifacts. This attack highlights the risks associated with trusting third-party actions in CI/CD pipelines and the potential for attackers to gain access to sensitive credentials and internal infrastructure.

## Attack Chain

1.  Attacker gains write access to the aquasecurity/trivy-action repository.
2.  Attacker modifies the entrypoint.sh script to include malicious code for credential theft.
3.  Attacker repoints existing release tags (e.g., 0.24.0) to the malicious commit.
4.  A GitHub Actions runner executes a workflow that uses the compromised trivy-action.
5.  The runner downloads and executes the malicious entrypoint.sh script.
6.  The malicious script enumerates process IDs (PIDs) running on the runner.
7.  The malicious script executes credential theft operations targeting runner secrets.
8.  The legitimate Trivy scanner runs (after the malicious code), masking the compromise.

## Impact

This supply chain attack allowed the attackers to steal sensitive credentials, API keys, and other secrets stored within the GitHub Actions runners. The compromised credentials could then be used to access internal infrastructure, cloud resources, and other sensitive systems. The CrowdStrike team detected the initial compromise across multiple Falcon platform customers, but the total number of affected organizations remains unknown. Successful exploitation could lead to data breaches, unauthorized access, and significant financial losses.

## Recommendation

*   Inspect your CI/CD pipelines for usage of the `aquasecurity/trivy-action` GitHub Action and verify the integrity of the referenced tag.
*   Implement stricter controls on third-party GitHub Actions used in CI/CD pipelines.
*   Monitor process execution on GitHub Actions runners for suspicious scripts and activity using the Sigma rule provided.
*   Enable process creation logging on Linux runners to capture the full execution chain and detect malicious script execution.
*   Implement network monitoring to detect unusual outbound connections from GitHub Actions runners, potentially indicating exfiltration of stolen credentials.
