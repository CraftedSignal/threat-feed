---
title: Trivy Security Scanner GitHub Actions Tag Hijacking for CI/CD Secret Theft
slug: 2026-03-trivy-tag-hijacking
description: Attackers hijacked 75 tags associated with the Trivy Security Scanner GitHub Actions to steal CI/CD secrets from users of the compromised tags.
date: "2026-03-21T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - supply-chain
  - github-actions
  - ci/cd
  - tag-hijacking
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://www.reddit.com/r/cybersecurity/comments/1rz38mv/trivy_security_scanner_github_actions_breached_75/
  - https://thehackernews.com/2026/03/trivy-security-scanner-github-actions.html
rules:
  - title: Detect Suspicious Outbound Connections from GitHub Actions
    description: Detects outbound network connections from GitHub Actions workflows that are not associated with known good processes.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect GitHub Actions Workflow Script Execution
    description: Detects execution of potentially malicious scripts within GitHub Actions workflows by monitoring for specific command line arguments.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On March 20, 2026, a breach was reported affecting the Trivy Security Scanner GitHub Actions. The incident involved the hijacking of 75 tags associated with the project. While the exact method of tag hijacking is not detailed, the attacker's objective was to steal CI/CD secrets. This attack could affect any project using the compromised tags in their GitHub Actions workflows. Successful exploitation allows an attacker to gain access to sensitive credentials, API keys, and other secrets stored within the CI/CD environment, leading to potential data breaches, supply chain compromise, and unauthorized access to critical systems. Defenders should focus on detecting and preventing unauthorized modifications to GitHub Action workflows and monitoring for suspicious access to CI/CD secrets.

## Attack Chain

1.  The attacker compromises the GitHub repository or account with permissions to manage tags for the Trivy Security Scanner GitHub Actions.
2.  The attacker creates or modifies existing tags (75 in this case) to point to malicious code repositories.
3.  Users unknowingly include the compromised tags in their GitHub Actions workflows, triggering the malicious code during CI/CD pipeline execution.
4.  The malicious code executes within the user's CI/CD environment, gaining access to environment variables and secrets.
5.  The attacker's code exfiltrates the stolen CI/CD secrets to an external server controlled by the attacker.
6.  The attacker uses the stolen secrets to gain unauthorized access to victim's systems, cloud resources, or code repositories.
7.  The attacker may further compromise the victim's infrastructure, inject malicious code into software builds, or steal sensitive data.

## Impact

This attack has the potential to impact a wide range of organizations that rely on the Trivy Security Scanner GitHub Actions in their CI/CD pipelines. The successful theft of CI/CD secrets can lead to significant data breaches, supply chain compromise, and unauthorized access to critical infrastructure. The scope of impact depends on the number of users affected by the compromised tags and the sensitivity of the secrets stored within their CI/CD environments. The incident could result in financial losses, reputational damage, and legal liabilities for affected organizations.

## Recommendation

*   Review GitHub Actions workflows for use of the compromised Trivy Security Scanner tags (reference: Overview).
*   Implement stricter access controls and multi-factor authentication for GitHub accounts with permissions to manage tags (reference: Attack Chain).
*   Deploy the Sigma rule to detect suspicious script execution within GitHub Actions workflows (reference: rules).
*   Monitor network traffic for unusual outbound connections originating from CI/CD environments, indicative of secret exfiltration (reference: rules).
*   Implement secrets scanning tools to detect exposed credentials and API keys within code repositories and CI/CD environments (reference: Attack Chain).
