---
title: GitHub Actions Workflow Command Injection via Issue Comments
slug: 2024-01-03-github-actions-injection
description: A GitHub Actions workflow uses untrusted user input from `issue_comment.body` directly inside a shell command, allowing potential command injection and arbitrary code execution on the runner.
date: "2024-01-03T17:23:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - github-actions
  - command-injection
  - ci-cd
vendors:
  - GitHub
products:
  - GitHub Actions
  - njzjz/wenxian
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-r4fj-r33x-8v88
rules:
  - title: Detect GitHub Actions Command Injection via Issue Comments
    description: Detects potential command injection attempts in GitHub Actions workflows triggered by issue comments by monitoring process creation with suspicious command line arguments indicative of shell injection.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect GitHub Actions workflow using backticks
    description: Detects GitHub Actions workflows using backticks which may propagate unsafe content.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A GitHub Actions workflow in the `actions/njzjz/wenxian` repository (versions <= 0.3.1) is vulnerable to command injection. The workflow is triggered by `issue_comment` events, which allows external users to inject arbitrary shell commands. The vulnerability arises because the workflow directly interpolates untrusted user input from `github.event.comment.body` into a shell command without proper sanitization. This occurs within the `run` context of a step, where `${{ }}` expressions are evaluated before execution. Successful exploitation allows remote attackers to execute arbitrary code on the runner, potentially compromising the CI/CD pipeline and exfiltrating sensitive data. This poses a significant risk to the integrity and confidentiality of the affected repository.

## Attack Chain

1. An attacker submits a malicious comment to a GitHub issue in the affected repository, crafted to exploit the command injection vulnerability.
2. The comment contains a payload designed to break out of the intended command context and inject arbitrary shell commands.
3. The GitHub Actions workflow is triggered by the `issue_comment` event.
4. The workflow executes the vulnerable step, which interpolates the attacker-controlled `github.event.comment.body` into a shell command. Specifically, the command `echo identifiers=$(echo "${{ github.event.comment.body }}" | grep -oE '@njzjz-bot .*' | head -n1 | cut -c12- | xargs) >> $GITHUB_OUTPUT` is executed.
5. The attacker's injected commands are executed on the GitHub Actions runner with the privileges of the runner environment.
6. The attacker could leverage access to the `GITHUB_TOKEN` to interact with the repository, potentially exfiltrating data or modifying code.
7. The attacker can use the injected commands to compromise the CI/CD pipeline.
8. The final objective is arbitrary code execution on the runner, data exfiltration, or CI/CD pipeline compromise.

## Impact

This vulnerability allows remote attackers to inject arbitrary shell commands into the GitHub Actions runner by posting malicious comments on issues. Successful exploitation can lead to the execution of arbitrary code within the runner environment. This could provide attackers with access to sensitive information, including the `GITHUB_TOKEN`, allowing them to exfiltrate repository data or modify code. The compromise of the CI/CD pipeline can lead to supply chain attacks and other severe consequences. The `actions/njzjz/wenxian` repository (vulnerable: <= 0.3.1) is affected by this vulnerability.

## Recommendation

*  Deploy the "Detect GitHub Actions Command Injection via Issue Comments" Sigma rule to detect exploitation attempts by monitoring process creation events with suspicious command line arguments.
*  Implement the suggested fix provided in the advisory by passing `github.event.comment.body` through an environment variable and referencing it safely within the script to mitigate the command injection vulnerability.
*  Audit all GitHub Actions workflows for similar vulnerabilities where untrusted user input is directly interpolated into shell commands, and apply proper sanitization techniques.
*  Patch `actions/njzjz/wenxian` to a version greater than 0.3.1 to remediate CVE-2026-34243.
