---
title: Langflow GitHub Actions Shell Injection Vulnerability
slug: 2026-03-langflow-shell-injection
description: Unauthenticated remote shell injection vulnerability exists in Langflow GitHub Actions workflows prior to version 1.9.0, enabling attackers to execute arbitrary shell commands via malicious branch names or pull request titles due to unsanitized GitHub context variable interpolation, leading to potential secret exfiltration and supply chain compromise.
date: "2026-03-25T12:00:00Z"
severities:
  - critical
tags:
  - shell-injection
  - github-actions
  - supply-chain
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33475
ioc_counts:
  url: 1
rules:
  - title: Detect Github Actions Shell Injection via Branch Name
    description: Detects potentially malicious branch names used in GitHub Actions pull requests that could lead to shell injection.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1588.006
    data_sources:
      - github
      - github_actions
  - title: Detect Github Actions Shell Injection via PR Title
    description: Detects potentially malicious PR Titles used in GitHub Actions that could lead to shell injection.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1588.006
    data_sources:
      - github
      - github_actions
rules_count: 2
---

Langflow, a tool for building and deploying AI-powered agents and workflows, is vulnerable to a critical shell injection flaw in its GitHub Actions workflows. Discovered in versions prior to 1.9.0 and assigned CVE-2026-33475, the vulnerability stems from unsanitized interpolation of GitHub context variables (e.g., `${{ github.head_ref }}`) within the `run:` steps of various workflow files. By crafting malicious branch names or pull request titles, attackers can inject and execute arbitrary…
