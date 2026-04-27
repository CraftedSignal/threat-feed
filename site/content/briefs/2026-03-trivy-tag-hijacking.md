---
title: Trivy Security Scanner GitHub Actions Tag Hijacking for CI/CD Secret Theft
slug: 2026-03-trivy-tag-hijacking
description: Attackers hijacked 75 tags associated with the Trivy Security Scanner GitHub Actions to steal CI/CD secrets from users of the compromised tags.
date: "2026-03-21T12:00:00Z"
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

On March 20, 2026, a breach was reported affecting the Trivy Security Scanner GitHub Actions. The incident involved the hijacking of 75 tags associated with the project. While the exact method of tag hijacking is not detailed, the attacker's objective was to steal CI/CD secrets. This attack could affect any project using the compromised tags in their GitHub Actions workflows. Successful exploitation allows an attacker to gain access to sensitive credentials, API keys, and other secrets stored…
