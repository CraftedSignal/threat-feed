---
title: OpenClaw Arbitrary Code Execution via Environment Variable Override (CVE-2026-41336)
slug: 2026-04-openclaw-env-override
description: OpenClaw before 2026.3.31 allows attackers to execute arbitrary code by overriding the OPENCLAW_BUNDLED_HOOKS_DIR environment variable using a workspace .env file, enabling the loading of attacker-controlled hook code.
date: "2026-04-24T12:00:00Z"
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

OpenClaw versions prior to 2026.3.31 are susceptible to an arbitrary code execution vulnerability, tracked as CVE-2026-41336. This flaw stems from the application's insecure handling of environment variables. Specifically, the OPENCLAW_BUNDLED_HOOKS_DIR environment variable, which dictates the directory from which OpenClaw loads bundled hooks, can be overridden by a workspace-specific .env file. This allows a malicious actor to craft a .env file within an untrusted workspace that points to a…
