---
title: OpenClaw CLI Backend Environment Variable Injection (CVE-2026-4039)
slug: 2026-04-openclaw-env-injection
description: OpenClaw versions prior to 2026.3.24 are vulnerable to environment variable injection via a malicious workspace configuration, potentially allowing attackers to execute arbitrary code.
date: "2026-04-08T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-4039
  - environment variable injection
  - openclaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-4039
    cvss: 6.3
    epss: 0.00087
references:
  - https://github.com/advisories/GHSA-vfw7-6rhc-6xxg
rules:
  - title: Detect OpenClaw CLI Execution with Suspicious Environment Variables
    description: Detects OpenClaw CLI execution with command line arguments indicative of environment variable injection attempts, by looking for common injection strings.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw CLI Modification Attempts via Environment Variables
    description: Detects attempts to modify OpenClaw behavior using environment variables, a common injection technique.
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

OpenClaw versions 2026.3.23-2 and earlier contain a vulnerability (CVE-2026-4039) that allows for environment variable injection when processing workspace configurations. An attacker can craft a malicious workspace configuration file that, when processed by the OpenClaw CLI backend, injects arbitrary environment variables. This can lead to the execution of arbitrary code with the privileges of the OpenClaw process. The vulnerability was reported by @YLChen-007 and a fix was implemented in…
