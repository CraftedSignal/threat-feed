---
brief_id: brief-2026-03-29-trivy-action-compromise
event_id: brief-2026-03-29-trivy-action-compromise
revision: 2
activity_at: "2026-03-29T14:22:47Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:9eb38c9637650efe76607ee8e1307bc42650a5b719d0713ad4662e15bacd33e8
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Compromised trivy-action GitHub Action Leads to Credential Theft
slug: 2026-03-29-trivy-action-compromise
description: The trivy-action GitHub Action was compromised through git tag repointing, injecting a multi-stage credential stealer into CI/CD pipelines that runs before the legitimate scanner.
date: "2026-03-29T14:22:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
tags:
  - supply-chain
  - credential-theft
  - github-actions
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious trivy-action Execution
    description: Detects execution of the trivy-action with suspicious arguments or parent processes, indicating potential compromise.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - process_creation
      - linux
  - title: Detect Process Enumeration in trivy-action
    description: Detects process enumeration commands within the trivy-action script, indicative of reconnaissance activity.
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

On March 20, 2026, CrowdStrike's Engineering team discovered a supply chain compromise affecting the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines. The attacker retroactively poisoned 76 out of 77 release tags by repointing them to malicious commits. This injected a multi-stage credential stealer that executes before the legitimate Trivy scanner, maintaining the appearance of normal workflow completion. The attack code, consisting of approximately 105 lines, targets secrets and credentials stored within the runner environment. This incident highlights the risks associated with mutable tags in Git and the potential for widespread impact through compromised CI/CD components. The initial spike in malicious activity was observed on Linux platforms linked to GitHub Actions runners on March 19, 2026.

## Attack Chain

1.  Attacker compromises the aquasecurity/trivy-action GitHub repository and modifies the release tags via git tag repointing.
2.  The malicious code is injected into the `entrypoint.sh` script of the trivy-action.
3.  A developer triggers a CI/CD pipeline that uses the compromised trivy-action (e.g., version 0.24.0).
4.  The GitHub Actions runner downloads and executes the malicious `entrypoint.sh` script.
5.  The malicious script enumerates process IDs (PIDs) to identify potential targets for credential theft.
6.  Credential theft occurs, targeting secrets and credentials available within the runner's environment.
7.  The legitimate Trivy scanner executes, masking the malicious activity and ensuring the workflow appears normal.
8.  Stolen credentials are used to access internal infrastructure, cloud resources, or other sensitive systems.

## Impact

This supply chain compromise has the potential to affect a large number of organizations using the trivy-action in their CI/CD pipelines. The silent nature of the credential theft allows attackers to gain unauthorized access to sensitive resources without immediately alerting victims. The compromised credentials can be used for lateral movement, data exfiltration, or further malicious activities within the victim's environment. The CrowdStrike team observed the initial spike of this compromise affecting multiple customers.

## Recommendation

*   Inspect your CI/CD pipelines for usage of `aquasecurity/trivy-action` and evaluate the risk of using mutable tags. Consider using specific commit SHAs instead of tags to ensure immutability.
*   Monitor process execution on GitHub Actions runners for suspicious activity originating from `entrypoint.sh` within the trivy-action directory, as described in the Attack Chain. Deploy the Sigma rule `Detect Suspicious trivy-action Execution` to your SIEM and tune for your environment.
*   Review and audit the secrets and credentials stored within your CI/CD environments to identify any potential unauthorized access or modifications.
*   Enable Sysmon process-creation logging on Linux runners to gain better visibility into process execution and detect malicious scripts. This will help activate the `Detect Suspicious trivy-action Execution` rule.
