---
title: OpenClaw Shell Wrapper Detection Bypass via Environment Variable Injection
slug: 2026-05-openclaw-shell-wrapper-bypass
description: OpenClaw versions before 2026.4.12 are vulnerable to environment variable injection, allowing attackers to bypass shell wrapper detection and manipulate execution semantics by modifying shell variables.
date: "2026-05-05T12:16:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - vulnerability
  - injection
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-42435
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42435
  - https://github.com/openclaw/openclaw/commit/8f8492d172f4c5b4fd7dd9a47855ed620c8770ab
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-j6c7-3h5x-99g9
  - https://www.vulncheck.com/advisories/openclaw-shell-wrapper-detection-bypass-via-environment-variable-assignment-injection
rules:
  - title: Detect Suspicious SHELLOPTS Modification
    description: Detects attempts to modify the SHELLOPTS environment variable, potentially indicating an exploitation attempt related to CVE-2026-42435.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious PS4 Modification
    description: Detects attempts to modify the PS4 environment variable, which could be used to manipulate shell tracing output and potentially bypass security controls.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.4.12 are susceptible to a shell-wrapper detection bypass vulnerability (CVE-2026-42435). This flaw allows attackers to inject arbitrary environment variable assignments at the argv level when OpenClaw processes shell commands. By carefully crafting these injections, attackers can bypass the expected preflight handling and subsequently manipulate high-risk shell variables, such as SHELLOPTS and PS4. This manipulation can lead to significant alterations in execution semantics and the circumvention of intended security controls within the OpenClaw environment. This vulnerability was reported on May 5, 2026, and affects systems running vulnerable versions of OpenClaw.

## Attack Chain

1. An attacker gains initial access to a system where OpenClaw is installed, potentially through exploiting another vulnerability or using compromised credentials.
2. The attacker identifies a point where OpenClaw executes shell commands with insufficient input sanitization.
3. The attacker crafts a command that injects environment variable assignments, such as `SHELLOPTS='-xe'` or `PS4='+ '`, at the argv level.
4. OpenClaw's exec preflight handling fails to properly detect and sanitize the injected environment variables.
5. The injected variables modify the behavior of subsequently executed shell commands. For instance, setting `SHELLOPTS='-xe'` enables verbose execution tracing.
6. If `PS4` is manipulated, this can alter the trace prompt, leading to information disclosure or further exploitation during script debugging.
7. The attacker leverages the modified shell environment to execute malicious code or bypass security restrictions.
8. The attacker achieves arbitrary code execution or privilege escalation by abusing the altered shell execution environment.

## Impact

Successful exploitation of CVE-2026-42435 allows attackers to manipulate the execution environment of shell commands within OpenClaw. This can lead to arbitrary code execution, privilege escalation, and the circumvention of security controls. While the specific number of affected installations is unknown, the impact is significant due to the potential for complete system compromise. Organizations using vulnerable versions of OpenClaw are at risk.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.12 or later to patch CVE-2026-42435.
*   Implement input validation and sanitization measures to prevent environment variable injection at the argv level.
*   Deploy the Sigma rule "Detect Suspicious SHELLOPTS Modification" to identify attempts to manipulate the SHELLOPTS environment variable.
*   Deploy the Sigma rule "Detect Suspicious PS4 Modification" to identify attempts to manipulate the PS4 environment variable.
