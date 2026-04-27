---
title: Gemini CLI Remote Code Execution via Workspace Trust and Tool Allowlisting Bypasses
slug: 2026-04-gemini-cli-rce
description: Gemini CLI is vulnerable to remote code execution via workspace trust and tool allowlisting bypasses, impacting headless mode and GitHub Actions workflows.
date: "2026-04-24T19:30:01Z"
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

Gemini CLI (`@google/gemini-cli`) versions prior to 0.39.1 and version 0.40.0-preview.2, along with the `run-gemini-cli` GitHub Action versions prior to 0.1.22, are susceptible to remote code execution due to insecure workspace trust handling and tool allowlisting bypasses. The vulnerability arises from the automatic trust of workspace folders in headless mode, allowing malicious environment variables within the `.gemini/` directory to be exploited. Furthermore, in `--yolo` mode, the tool…
