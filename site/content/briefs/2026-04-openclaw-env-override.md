---
title: OpenClaw Workspace .env Overrides Bundled Plugin Trust Root
slug: 2026-04-openclaw-env-override
description: OpenClaw versions up to 2026.3.28 are vulnerable to a workspace-level .env file overriding the bundled plugin trust root, potentially allowing for the execution of malicious plugins when an attacker-controlled workspace is loaded.
date: "2026-04-03T02:48:24Z"
type: coverage
types:
  - coverage
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

OpenClaw, a workspace application, is susceptible to a vulnerability where the `OPENCLAW_BUNDLED_PLUGINS_DIR` environment variable can be overridden by a `.env` file within a workspace. This allows a malicious actor to craft a workspace containing a `.env` file that points to a directory containing malicious plugins. If a user opens this attacker-controlled workspace in a vulnerable version of OpenClaw (<= 2026.3.28), the application will load and execute these malicious plugins. This vulnerability was reported by @nexrin and patched in version 2026.3.31. The risk is elevated when OpenClaw is used to process workspaces from untrusted sources.

## Attack Chain

1. Attacker crafts a malicious OpenClaw workspace.
2. Within the workspace, the attacker creates a `.env` file.
3. The `.env` file contains the line `OPENCLAW_BUNDLED_PLUGINS_DIR=/path/to/attacker/plugins`.
4. The attacker places malicious plugins in the directory specified by `/path/to/attacker/plugins`. These could be JavaScript or other executable formats depending on OpenClaw's plugin architecture.
5. The attacker distributes the malicious workspace to a victim. This could be via email, shared storage, or other means.
6. The victim opens the malicious workspace with a vulnerable version of OpenClaw (<= 2026.3.28).
7. OpenClaw reads the `.env` file and sets the `OPENCLAW_BUNDLED_PLUGINS_DIR` environment variable accordingly.
8. OpenClaw loads and executes the attacker-controlled plugins from the specified directory, leading to arbitrary code execution within the context of the OpenClaw process.

## Impact

Successful exploitation allows an attacker to execute arbitrary code within the OpenClaw environment. The impact could include data theft, modification of workspace files, or further compromise of the victim's system. The severity is tied to user interaction as the victim must open the attacker-crafted workspace. While the number of affected users is not specified in the advisory, organizations using OpenClaw for sensitive projects are most at risk.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to remediate the vulnerability.
*   Deploy the Sigma rule `Detect OpenClaw Plugin Directory Override` to detect attempts to override the plugin directory via `.env` files.
*   Implement file integrity monitoring for OpenClaw workspaces to detect unauthorized modifications to `.env` files.
*   Educate users about the risks of opening workspaces from untrusted sources.
