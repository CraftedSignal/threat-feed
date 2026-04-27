---
title: Mise Trust Bypass Vulnerability via Malicious .mise.toml
slug: 2026-04-mise-trust-bypass
description: A vulnerability in mise allows an attacker who can place a malicious .mise.toml file in a repository to bypass trust checks and execute arbitrary code via `[env] _.source` due to improper loading of trust settings.
date: "2026-04-07T20:13:11Z"
severities:
  - high
tags:
  - mise
  - trust-bypass
  - code-execution
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
references:
  - https://github.com/advisories/GHSA-436v-8fw5-4mj8
rules:
  - title: Detect Mise Hook-Env with Dot Source
    description: Detects the execution of `mise hook-env` with a potentially malicious `.source` directive within the .mise.toml file, indicating a possible trust bypass attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Creation by Mise
    description: Detects suspicious file creation, such as in /tmp, by the mise process, which could indicate arbitrary code execution following a trust bypass.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability exists in the mise tool (versions 2026.2.18 through 2026.4.5) where local project configuration files (.mise.toml) are loaded *before* trust checks are performed. This allows an attacker who can influence the contents of a repository (e.g., through a pull request or direct commit) to inject malicious configurations that bypass intended trust restrictions. Specifically, an attacker can set `trusted_config_paths = ["/"]` within a crafted .mise.toml, which effectively…
