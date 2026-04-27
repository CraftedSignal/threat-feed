---
title: GitPython Command Injection Vulnerability
slug: 2024-01-09-gitpython-cmd-injection
description: GitPython versions 3.1.30 through 3.1.46 are vulnerable to command injection by passing attacker-controlled kwargs into `Repo.clone_from()`, `Remote.fetch()`, `Remote.pull()`, or `Remote.push()`, leading to arbitrary command execution due to bypassed safety checks.
date: "2024-01-09T10:00:00Z"
severities:
  - high
tags:
  - command-injection
  - gitpython
  - vulnerability
vendors:
  - pip
products:
  - GitPython (3.1.30-3.1.46)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-rpm5-65cw-6hj4
rules:
  - title: Detect GitPython Kwarg Command Injection
    description: Detects potential command injection attempts via GitPython by identifying calls to Repo.clone_from, Remote.fetch, Remote.pull, or Remote.push with potentially malicious kwargs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
  - title: Detect GitPython Kwarg Command Injection via Modified Process Name
    description: Detects potential command injection attempts via GitPython by identifying calls to Repo.clone_from, Remote.fetch, Remote.pull, or Remote.push with potentially malicious kwargs when the python process name has been changed.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

GitPython, a library providing programmatic interaction with Git repositories, is susceptible to a command injection vulnerability in versions 3.1.30 to 3.1.46. The vulnerability stems from insufficient validation of keyword arguments (kwargs) passed to functions like `Repo.clone_from()`, `Remote.fetch()`, `Remote.pull()`, and `Remote.push()`. Specifically, when underscore-form kwargs (e.g., `upload_pack`) are used, they bypass the intended safety checks designed to prevent the execution of…
