---
title: 'GitHub Copilot CLI: Nested Bare Repository RCE via Git Configuration'
slug: 2026-05-github-copilot-cli-rce
description: GitHub Copilot CLI versions prior to 1.0.43 are vulnerable to arbitrary code execution via a malicious bare git repository nested within a project directory, exploiting git's automatic bare repository discovery and the `core.fsmonitor` configuration setting.
date: "2026-05-11T16:17:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - git
  - rce
  - github
  - code execution
vendors:
  - GitHub
products:
  - Copilot CLI (<= 1.0.42)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-9ccr-r5hg-74gf
  - CVE-2026-45033
rules:
  - title: Detect Suspicious Git Configuration Modification
    description: Detects modification of git configuration to set suspicious commands, which could indicate an attempt to exploit CVE-2026-45033.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - windows
  - title: Detect Git Command Execution from Unusual Locations
    description: Detects execution of git commands from locations other than the standard git install directory. This might indicate exploitation of CVE-2026-45033 via core.fsmonitor.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A security vulnerability exists in GitHub Copilot CLI versions prior to 1.0.43 that allows for arbitrary code execution. The vulnerability stems from how Git handles bare repositories nested within a project directory. An attacker can create a malicious bare Git repository with a specially crafted configuration. When GitHub Copilot CLI performs Git operations, it may inadvertently discover and read the configuration of the malicious bare repository, leading to the execution of arbitrary commands defined within settings like `core.fsmonitor`. This poses a significant risk, as the execution occurs without user consent or awareness. This vulnerability was addressed in version 1.0.43 by setting `safe.bareRepository=explicit` through environment variables.

## Attack Chain

1. An attacker crafts a malicious bare Git repository.
2. The attacker nests the malicious repository within a project directory (e.g., `vendor/malicious.git/`).
3. The attacker configures the `core.fsmonitor` setting within the malicious bare repository to execute arbitrary commands. Other settings like `core.hookspath`, `diff.external`, and `merge.tool` could also be targeted.
4. A user clones or otherwise acquires the project containing the malicious repository. This could occur through a pull request, dependency, or other means.
5. GitHub Copilot CLI performs a Git operation (e.g., `git status`, `git diff`, `git rev-parse`) that traverses into or through the directory containing the malicious bare repository.
6. Git automatically discovers the bare repository during directory traversal.
7. Git reads the configuration of the discovered bare repository, including the attacker-controlled `core.fsmonitor` setting.
8. The attacker's arbitrary command is executed on the user's system, leading to potential data exfiltration, credential theft, file modification, or further system compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve arbitrary code execution on a user's workstation whenever GitHub Copilot CLI performs Git operations near the malicious directory. This could lead to data exfiltration, credential theft, file modification, or further system compromise. The vulnerable versions of GitHub Copilot CLI are those prior to 1.0.43. The vulnerability highlights the danger of trusting implicitly-configured Git repositories within a project.

## Recommendation

*   Upgrade GitHub Copilot CLI to version 1.0.43 or later to incorporate the fix for CVE-2026-45033.
*   Deploy the Sigma rule "Detect Suspicious Git Configuration Modification" to monitor for unauthorized changes to Git configuration settings.
*   Enable process creation logging to detect execution from unusual git configuration locations, as detected by the rule "Detect Git Command Execution from Unusual Locations".
