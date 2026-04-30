---
title: OpenClaw Exec Allowlist Bypass via POSIX Path Overmatching (CVE-2026-32973)
slug: 2026-03-openclaw-bypass
description: OpenClaw before 2026.3.11 contains an exec allowlist bypass vulnerability (CVE-2026-32973) due to improper normalization of patterns, allowing attackers to execute unintended commands via wildcard matching in POSIX paths.
date: "2026-03-29T13:17:01Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-32973
  - openclaw
  - allowlist-bypass
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32973
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-f8r2-vg7x-gh8m
  - https://www.vulncheck.com/advisories/openclaw-exec-allowlist-pattern-overmatch-via-posix-path-normalization
rules:
  - title: Detect OpenClaw Allowlist Bypass Attempt
    description: Detects attempts to bypass the OpenClaw exec allowlist by using wildcard characters in command execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw using Lowercase Bypass
    description: Detects potential bypass attempts leveraging lowercase normalization issues in OpenClaw's allowlist.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.11 are susceptible to an exec allowlist bypass vulnerability, identified as CVE-2026-32973. The vulnerability stems from the `matchesExecAllowlistPattern` function's flawed normalization process, specifically its handling of lowercasing and glob matching. This leads to overmatching on POSIX paths, enabling attackers to circumvent intended restrictions. By leveraging the '?' wildcard, attackers can match across path segments to execute commands or access paths…
