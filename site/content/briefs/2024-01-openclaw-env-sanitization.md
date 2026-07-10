---
title: OpenClaw Inconsistent Host Exec Environment Override Sanitization
slug: 2024-01-openclaw-env-sanitization
description: OpenClaw versions before 2026.3.22 have an inconsistent host execution environment override sanitization, allowing blocked or malformed override keys to bypass sanitization, which could lead to unauthorized access or code execution.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - sanitization
  - vulnerability
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-39pp-xp36-q6mg
rules:
  - title: Detect OpenClaw Environment Override
    description: Detects attempts to set environment variables during OpenClaw execution which might indicate an exploit attempt.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw Malformed Environment Variable Key
    description: Detects attempts to set malformed environment variable keys during OpenClaw execution.
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

The OpenClaw package, a tool used for gateway host execution, suffered from an inconsistent sanitization of host environment overrides in versions prior to 2026.3.22. This vulnerability allowed blocked or malformed override keys to slip through due to inconsistent sanitization paths within the application. The lack of consistent enforcement of the shared host environment policy meant that attackers could potentially manipulate environment variables in a way that was not intended by the application developers. This poses a significant risk, as attackers could potentially inject malicious code or alter application behavior by exploiting this sanitization flaw. The vulnerability was reported by @zpbrent and patched in version 2026.3.22.

## Attack Chain

Due to the nature of the vulnerability (inconsistent sanitization) and the available information, a complete attack chain cannot be constructed. However, the following hypothetical steps could be envisioned based on the vulnerability description:

1. An attacker identifies an OpenClaw instance running a version prior to 2026.3.22.
2. The attacker crafts a malicious request that includes environment variable overrides.
3. The malicious request is sent to the OpenClaw gateway.
4. The request is handled by `bash-tools.exec.ts` or `node-host/invoke-system-run.ts`
5. Due to the lack of consistent sanitization in `host-env-security.ts`, a blocked or malformed environment variable override key is not properly sanitized.
6. The unsanitized environment variable override is passed to the host operating system.
7. The host operating system executes a command, using the attacker-controlled environment variable.
8. The attacker gains unauthorized access or executes arbitrary code on the host.

## Impact

Successful exploitation of this vulnerability could lead to a variety of negative outcomes, including unauthorized access to sensitive data, arbitrary code execution on the host system, and potential compromise of the entire gateway infrastructure. While the number of affected installations is unknown, the "high" severity rating indicates the potential for significant damage. The affected package is `openclaw` on npm.

## Recommendation

*   Upgrade the `openclaw` package to version 2026.3.22 or later to remediate the vulnerability.
*   Inspect the `src/infra/host-env-security.ts` file in patched versions to understand the implemented sanitization mechanisms and ensure these mechanisms are effectively applied to all relevant execution paths.
*   Implement monitoring for unexpected environment variable changes during OpenClaw execution to detect potential exploitation attempts. This might require custom logging or auditing rules depending on the deployment environment.
*   Deploy the Sigma rule `Detect OpenClaw Environment Override` to identify attempts to set suspicious environment variables within the application.
