---
title: Electerm Command Injection Vulnerability via runLinux Function
slug: 2024-01-electerm-command-injection
description: A command injection vulnerability exists in electerm's install.js due to insufficient validation in the runLinux() function, allowing attackers to execute arbitrary commands by manipulating remote release metadata.
date: "2024-01-03T12:00:00Z"
severities:
  - critical
tags:
  - command-injection
  - electerm
  - npm
products:
  - electerm
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-8x35-hph8-37hq
  - https://github.com/electerm/electerm/commit/59708b38c8a52f5db59d7d4eff98e31d573128ee
rules:
  - title: Electerm NPM install Command Injection
    description: Detects command injection attempts during npm install of electerm package by monitoring process execution with suspicious command line arguments.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious Child Processes of NPM
    description: Detects suspicious child processes spawned by npm, indicating potential command injection exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical command injection vulnerability has been identified in Electerm, specifically affecting users who install the application via `npm install -g electerm` on Linux systems. The vulnerability resides within the `runLinux()` function in `github.com/elcterm/electerm/npm/install.js`. This function lacks proper validation when appending remote version strings into an `exec("rm -rf ...")` command. An attacker capable of controlling the remote release metadata (e.g., version string, release…
