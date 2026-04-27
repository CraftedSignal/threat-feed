---
title: GitPython Vulnerability Allows Arbitrary Code Execution via Git Hooks
slug: 2024-01-23-gitpython-hook-execution
description: A vulnerability in GitPython versions prior to 3.1.47 allows for command execution during repository cloning by manipulating the `multi_options` parameter to inject malicious Git configurations, such as `core.hooksPath`, leading to the execution of attacker-controlled hooks.
date: "2024-01-23T12:00:00Z"
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

GitPython before version 3.1.47 is susceptible to a command execution vulnerability. The issue stems from how the `_clone()` function validates the `multi_options` parameter used in the `clone_from()`, `clone()`, or `Submodule.update()` methods. Specifically, the validation occurs on the original list of options before the `shlex.split` transformation. This allows an attacker to craft a string like `"--branch main --config core.hooksPath=/x"` which passes the initial validation because it…
