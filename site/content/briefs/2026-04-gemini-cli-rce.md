---
title: Gemini CLI Remote Code Execution via Workspace Trust and Tool Allowlisting Bypasses
slug: 2026-04-gemini-cli-rce
description: Gemini CLI is vulnerable to remote code execution via workspace trust and tool allowlisting bypasses, impacting headless mode and GitHub Actions workflows.
date: "2026-04-24T19:30:01Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - rce
  - supply-chain
  - github-actions
vendors:
  - Google
products:
  - Gemini CLI
  - run-gemini-cli GitHub Action
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-wpqr-6v78-jr5g
rules:
  - title: Detect Gemini CLI run_shell_command in CI/CD Pipelines
    description: Detects the use of run_shell_command within CI/CD pipeline contexts, which could be indicative of command injection vulnerabilities in older Gemini CLI versions.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect Gemini CLI with --yolo flag
    description: Detects the usage of the --yolo flag with Gemini CLI, which bypasses tool allowlisting in older versions and could lead to command execution vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Gemini CLI (`@google/gemini-cli`) versions prior to 0.39.1 and version 0.40.0-preview.2, along with the `run-gemini-cli` GitHub Action versions prior to 0.1.22, are susceptible to remote code execution due to insecure workspace trust handling and tool allowlisting bypasses. The vulnerability arises from the automatic trust of workspace folders in headless mode, allowing malicious environment variables within the `.gemini/` directory to be exploited. Furthermore, in `--yolo` mode, the tool allowlist was previously ignored, enabling prompt injection and code execution via commands like `run_shell_command`. This poses a risk, especially in CI/CD environments that process untrusted inputs such as pull requests. The patched version 0.39.1 enforces explicit folder trust in headless mode and properly evaluates tool allowlists under `--yolo`, mitigating these risks. This impacts all Gemini CLI GitHub Actions and requires users to review their workflows.

## Attack Chain

1.  Attacker submits a malicious pull request to a repository using Gemini CLI in a GitHub Actions workflow.
2.  The workflow, running in headless mode, automatically trusts the workspace folder (versions prior to 0.39.1).
3.  The attacker's pull request includes a crafted `.gemini/` directory containing malicious environment variables.
4.  Gemini CLI loads the malicious environment variables, leading to code execution.
5.  Alternatively, the attacker injects a malicious prompt leveraging `run_shell_command` when `--yolo` is used.
6.  The `run_shell_command` executes arbitrary commands on the runner due to the bypassed tool allowlist (versions prior to 0.39.1).
7.  The attacker gains control of the CI/CD runner, potentially exfiltrating secrets or injecting malicious code into the deployment pipeline.
8.  Successful exploitation leads to code execution on the CI/CD runner, data exfiltration, or supply chain compromise.

## Impact

The vulnerability impacts workflows utilizing Gemini CLI in headless mode, particularly those processing untrusted inputs such as pull requests from external contributors. Successful exploitation can lead to remote code execution on the CI/CD runner, potentially enabling attackers to exfiltrate sensitive information, such as API keys and credentials, or inject malicious code into the application deployment pipeline. This can lead to a supply chain compromise. All Gemini CLI GitHub Actions are affected, requiring users to review and update their workflows.

## Recommendation

*   Upgrade `@google/gemini-cli` to version 0.39.1 or later, or 0.40.0-preview.3 if using a preview version.
*   Upgrade `actions/google-github-actions/run-gemini-cli` to version 0.1.22 or later.
*   For workflows running on trusted inputs, set `GEMINI_TRUST_WORKSPACE: 'true'` in the GitHub Actions workflow.
*   For workflows processing untrusted inputs, review the hardening guidance in [google-github-actions/run-gemini-cli](https://github.com/google-github-actions/run-gemini-cli) and set the environment variable accordingly.
*   Review and harden tool allowlists in `~/.gemini/settings.json` to restrict the commands that can be executed, especially when using the `--yolo` flag.
