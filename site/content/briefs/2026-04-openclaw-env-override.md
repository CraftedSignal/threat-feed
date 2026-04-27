---
title: OpenClaw Workspace .env Hook Override Vulnerability
slug: 2026-04-openclaw-env-override
description: The openclaw package is vulnerable to a high severity issue where a workspace's `.env` file can override the `OPENCLAW_BUNDLED_HOOKS_DIR`, allowing attackers to replace trusted hooks with malicious code.
date: "2026-04-02T21:00:16Z"
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

The `openclaw` package, a yet-to-be-defined tool, is vulnerable to a critical flaw affecting versions 2026.3.28 and earlier. This vulnerability stems from the application's susceptibility to having its default hook directory, designated by the `OPENCLAW_BUNDLED_HOOKS_DIR` environment variable, overridden by settings defined within a workspace's `.env` file. An attacker could leverage this vulnerability within an untrusted workspace to replace trusted, default-on bundled hooks with malicious…
