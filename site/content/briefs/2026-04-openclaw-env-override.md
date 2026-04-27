---
title: OpenClaw Workspace .env Overrides Bundled Plugin Trust Root
slug: 2026-04-openclaw-env-override
description: OpenClaw versions up to 2026.3.28 are vulnerable to a workspace-level .env file overriding the bundled plugin trust root, potentially allowing for the execution of malicious plugins when an attacker-controlled workspace is loaded.
date: "2026-04-03T02:48:24Z"
severities:
  - medium
tags:
  - openclaw
  - plugin-security
  - env-variable-override
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Impair Defenses
references:
  - https://github.com/advisories/GHSA-qcj9-wwgw-6gm8
rules:
  - title: Detect OpenClaw Plugin Directory Override
    description: Detects attempts to override the OpenClaw plugin directory using a .env file. This may indicate a malicious workspace attempting to load untrusted plugins.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious File Creation in OpenClaw Plugin Directory
    description: Detects creation of executable files (e.g., .js, .py, .sh) within the OpenClaw plugin directory. Requires auditd or similar filesystem monitoring.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw, a workspace application, is susceptible to a vulnerability where the `OPENCLAW_BUNDLED_PLUGINS_DIR` environment variable can be overridden by a `.env` file within a workspace. This allows a malicious actor to craft a workspace containing a `.env` file that points to a directory containing malicious plugins. If a user opens this attacker-controlled workspace in a vulnerable version of OpenClaw (<= 2026.3.28), the application will load and execute these malicious plugins. This…
