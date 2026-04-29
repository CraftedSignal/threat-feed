---
title: OpenClaw Workspace .env Hook Override Vulnerability
slug: 2026-04-openclaw-env-override
description: The openclaw package is vulnerable to a high severity issue where a workspace's `.env` file can override the `OPENCLAW_BUNDLED_HOOKS_DIR`, allowing attackers to replace trusted hooks with malicious code.
date: "2026-04-02T21:00:16Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - openclaw
  - env-override
  - hook-injection
references:
  - https://github.com/advisories/GHSA-3qpv-xf3v-mm45
rules:
  - title: Detect OpenClaw Bundled Hooks Override via .env
    description: Detects modifications to .env files that override the OPENCLAW_BUNDLED_HOOKS_DIR environment variable, indicating a potential hook injection attempt.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - file_event
      - linux
  - title: Detect Execution from Non-Standard OpenClaw Hook Directory
    description: Detects execution of scripts or binaries from a directory specified by OPENCLAW_BUNDLED_HOOKS_DIR in the .env file, indicating a potential hook injection attempt.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `openclaw` package, a yet-to-be-defined tool, is vulnerable to a critical flaw affecting versions 2026.3.28 and earlier. This vulnerability stems from the application's susceptibility to having its default hook directory, designated by the `OPENCLAW_BUNDLED_HOOKS_DIR` environment variable, overridden by settings defined within a workspace's `.env` file. An attacker could leverage this vulnerability within an untrusted workspace to replace trusted, default-on bundled hooks with malicious code. Version 2026.3.31 resolves this issue. This vulnerability was reported by @nexrin.

## Attack Chain

1. An attacker gains access to or creates a workspace where OpenClaw is used.
2. The attacker crafts a malicious `.env` file within the workspace.
3. The malicious `.env` file defines `OPENCLAW_BUNDLED_HOOKS_DIR` and sets it to a directory controlled by the attacker.
4. The attacker places malicious hook scripts (e.g., JavaScript, Python, or shell scripts) within the attacker-controlled directory. These scripts are designed to execute arbitrary code.
5. When OpenClaw initializes within the workspace, it reads the `.env` file and uses the attacker-controlled directory as the location for bundled hooks, instead of the intended secure location.
6. OpenClaw executes the malicious hook scripts as part of its normal operation.
7. The attacker achieves code execution within the context of the OpenClaw process.
8. The attacker leverages the code execution to establish persistence or escalate privileges on the affected system.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code within the context of the OpenClaw application. Depending on how OpenClaw is implemented and the privileges it operates with, this could lead to complete system compromise. This could impact any environment where OpenClaw is used to manage or automate tasks within workspaces.

## Recommendation

*   Upgrade the `openclaw` package to version 2026.3.31 or later to patch the vulnerability.
*   Monitor for modifications to `.env` files within OpenClaw workspaces, looking for changes to the `OPENCLAW_BUNDLED_HOOKS_DIR` environment variable. Deploy the "Detect OpenClaw Bundled Hooks Override via .env" Sigma rule to detect this.
*   Implement strict access controls on OpenClaw workspaces to prevent unauthorized users from modifying `.env` files.
