---
title: OpenClaw Sandbox Boundary Bypass Vulnerability (CVE-2026-32988)
slug: 2026-03-openclaw-sandbox-bypass
description: OpenClaw before 2026.3.11 is vulnerable to a sandbox boundary bypass (CVE-2026-32988) due to improper handling of temporary files in fs-bridge staged writes, allowing attackers to potentially write arbitrary bytes outside the intended validated path.
date: "2026-03-31T12:16:30Z"
severities:
  - high
tags:
  - sandbox-bypass
  - race-condition
  - cve-2026-32988
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32988
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32988
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-mj4p-rc52-m843
  - https://www.vulncheck.com/advisories/openclaw-sandbox-boundary-bypass-via-unvalidated-temporary-file-creation
rules:
  - title: Detect OpenClaw Suspicious Temporary File Creation
    description: Detects the creation of temporary files that might indicate an attempt to exploit the CVE-2026-32988 vulnerability in OpenClaw's fs-bridge staged writes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
  - title: Detect OpenClaw fs-bridge Staged Writes to Unexpected Paths
    description: Detects file writes to unexpected paths during OpenClaw's fs-bridge staged write process which could indicate a sandbox escape.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.11 are susceptible to a sandbox boundary bypass vulnerability identified as CVE-2026-32988. This flaw resides in the fs-bridge staged writes mechanism, where the creation and population of temporary files lack proper validation to ensure they remain within a verified parent directory. This vulnerability stems from a race condition involving parent-path alias changes. An attacker can exploit this condition to manipulate file writes, allowing attacker-controlled…
