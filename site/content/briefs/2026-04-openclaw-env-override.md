---
title: OpenClaw Arbitrary Code Execution via Environment Variable Override (CVE-2026-41336)
slug: 2026-04-openclaw-env-override
description: OpenClaw before 2026.3.31 allows attackers to execute arbitrary code by overriding the OPENCLAW_BUNDLED_HOOKS_DIR environment variable using a workspace .env file, enabling the loading of attacker-controlled hook code.
date: "2026-04-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - code-execution
  - environment-variable-override
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
cves:
  - id: CVE-2026-41336
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41336
  - https://github.com/openclaw/openclaw/commit/330a9f98cb29c79b1c16a2117e03d6276a0d6289
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-3qpv-xf3v-mm45
  - https://www.vulncheck.com/advisories/openclaw-arbitrary-hook-code-execution-via-openclaw-bundled-hooks-dir-environment-variable-override
rules:
  - title: OpenClaw Suspicious Process Creation
    description: Detects suspicious processes spawned by OpenClaw, indicating potential code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: OpenClaw Environment Variable Override
    description: Detects attempts to override the OPENCLAW_BUNDLED_HOOKS_DIR environment variable, potentially leading to code execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

OpenClaw versions prior to 2026.3.31 are susceptible to an arbitrary code execution vulnerability, tracked as CVE-2026-41336. This flaw stems from the application's insecure handling of environment variables. Specifically, the OPENCLAW_BUNDLED_HOOKS_DIR environment variable, which dictates the directory from which OpenClaw loads bundled hooks, can be overridden by a workspace-specific .env file. This allows a malicious actor to craft a .env file within an untrusted workspace that points to a directory containing attacker-controlled hook code. Upon loading the workspace, OpenClaw will execute the malicious code, effectively granting the attacker arbitrary code execution within the application's context. This vulnerability poses a significant risk to systems utilizing OpenClaw, as it can lead to complete system compromise.

## Attack Chain

1.  The attacker creates a malicious hook code file (e.g., `evil_hook.py`) containing arbitrary code to be executed.
2.  The attacker creates a directory (e.g., `/tmp/evil_hooks`) and places the malicious hook code file within it.
3.  The attacker crafts a `.env` file containing the line `OPENCLAW_BUNDLED_HOOKS_DIR=/tmp/evil_hooks`.
4.  The attacker places the malicious `.env` file into a workspace that a victim user is likely to open within OpenClaw.
5.  The victim user opens the workspace within OpenClaw.
6.  OpenClaw reads the `.env` file and overrides the default `OPENCLAW_BUNDLED_HOOKS_DIR` with the attacker-controlled path `/tmp/evil_hooks`.
7.  OpenClaw loads and executes the malicious hook code from `evil_hook.py`, granting the attacker arbitrary code execution.
8.  The attacker gains control of the OpenClaw process and potentially the underlying system.

## Impact

Successful exploitation of CVE-2026-41336 allows an attacker to execute arbitrary code within the context of the OpenClaw application. This could lead to the complete compromise of the affected system, including data theft, modification, or destruction. Given the nature of the vulnerability, any system running a vulnerable version of OpenClaw is at risk if it processes untrusted workspaces. The CVSS v3.1 base score of 7.8 reflects the high potential impact of this vulnerability.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to patch CVE-2026-41336.
*   Implement strict workspace validation to prevent the loading of malicious `.env` files.
*   Monitor process creations originating from the OpenClaw process for suspicious activity using the `OpenClaw Suspicious Process Creation` Sigma rule.
*   Deploy the `OpenClaw Environment Variable Override` Sigma rule to detect attempts to override the OPENCLAW_BUNDLED_HOOKS_DIR variable.
