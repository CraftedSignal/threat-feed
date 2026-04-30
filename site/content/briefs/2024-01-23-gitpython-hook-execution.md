---
title: GitPython Vulnerability Allows Arbitrary Code Execution via Git Hooks
slug: 2024-01-23-gitpython-hook-execution
description: A vulnerability in GitPython versions prior to 3.1.47 allows for command execution during repository cloning by manipulating the `multi_options` parameter to inject malicious Git configurations, such as `core.hooksPath`, leading to the execution of attacker-controlled hooks.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - gitpython
  - code-execution
  - git-hooks
  - command-injection
vendors:
  - pip
products:
  - GitPython
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2023-40267
    cvss: 9.8
    epss: 0.00351
references:
  - https://github.com/advisories/GHSA-x2qx-6953-8485
rules:
  - title: Detect Suspicious Git Hook Execution
    description: Detects execution of git hooks from unusual paths, which may indicate exploitation of Git related vulnerabilities
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Git Config Setting core.hooksPath via CommandLine
    description: Detects attempts to set the git config core.hooksPath via command line, potentially indicating an attempt to inject malicious hooks
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

GitPython before version 3.1.47 is susceptible to a command execution vulnerability. The issue stems from how the `_clone()` function validates the `multi_options` parameter used in the `clone_from()`, `clone()`, or `Submodule.update()` methods. Specifically, the validation occurs on the original list of options before the `shlex.split` transformation. This allows an attacker to craft a string like `"--branch main --config core.hooksPath=/x"` which passes the initial validation because it starts with a safe option (`--branch`). However, after the string is split into tokens, the `--config` option becomes active, allowing the attacker to inject a malicious `core.hooksPath` configuration. This configuration points Git to a directory containing attacker-controlled Git hooks, which are then executed during the clone operation. This vulnerability is similar in nature to CVE-2023-40267.

## Attack Chain

1. An attacker identifies a vulnerable application using GitPython to clone repositories.
2. The attacker crafts a malicious string containing a Git configuration option, such as `--config core.hooksPath=/path/to/malicious/hooks`, embedded within a seemingly benign option string like `--branch main --config core.hooksPath=/path/to/malicious/hooks`.
3. The attacker injects this malicious string into the `multi_options` parameter of the `clone_from()`, `clone()`, or `Submodule.update()` methods.
4. GitPython's `_clone()` function validates the `multi_options` parameter using `Git.check_unsafe_options()` *before* it is processed by `shlex.split()`.
5. Because the malicious string starts with a safe option (`--branch`), it bypasses the validation check.
6. The `shlex.split()` function then transforms the string into a list of individual options, making the `--config` option active.
7. The `git clone` command is executed with the injected `--config core.hooksPath=/path/to/malicious/hooks` option, causing Git to use the attacker-controlled directory for Git hooks.
8. Git executes the malicious hooks (e.g., `post-checkout`), resulting in arbitrary code execution on the victim's machine.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the system where the GitPython library is used. Any application that passes user-supplied input to the `multi_options` parameter of the affected functions is vulnerable. This can lead to complete system compromise, data exfiltration, or denial of service. The vulnerability affects GitPython versions prior to 3.1.47.

## Recommendation

*   Upgrade GitPython to version 3.1.47 or later to patch the vulnerability (Affected Packages).
*   Implement input validation and sanitization for any user-supplied input used to construct the `multi_options` parameter to prevent injection of malicious Git configurations (Code).
*   Monitor process creation events for the execution of unexpected processes from directories specified as `core.hooksPath` (see Sigma rule `Detect Suspicious Git Hook Execution`).
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
