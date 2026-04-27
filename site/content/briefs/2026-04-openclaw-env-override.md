---
title: OpenClaw Environment Variable Override Vulnerability (CVE-2026-35650)
slug: 2026-04-openclaw-env-override
description: OpenClaw before 2026.3.22 contains an environment variable override handling vulnerability that allows attackers to bypass shared host environment policies through inconsistent sanitization, leading to arbitrary code execution.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-35650
  - environment variable override
  - privilege escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35650
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35650
  - https://github.com/openclaw/openclaw/commit/630f1479c44f78484dfa21bb407cbe6f171dac87
  - https://github.com/openclaw/openclaw/commit/7abfff756d6c68d17e21d1657bbacbaec86de232
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-39pp-xp36-q6mg
  - https://www.vulncheck.com/advisories/openclaw-environment-variable-override-bypass-via-inconsistent-sanitization
rules:
  - title: Detect OpenClaw Environment Variable Overrides
    description: Detects processes with unusual environment variables indicative of CVE-2026-35650 exploitation in OpenClaw.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect OpenClaw Malformed Environment Variable Override Attempts
    description: Detects attempts to exploit OpenClaw via malformed or blocked environment variable overrides.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.22 are susceptible to an environment variable override vulnerability (CVE-2026-35650). This flaw arises from inconsistent sanitization paths within the application's handling of environment variable overrides. An attacker can exploit this vulnerability by supplying blocked or malformed override keys that bypass validation mechanisms. Successful exploitation allows an attacker with low privileges to execute arbitrary code with unintended environment variables…
