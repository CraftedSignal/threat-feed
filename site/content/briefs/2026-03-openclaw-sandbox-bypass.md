---
title: OpenClaw Sandbox Boundary Bypass Vulnerability (CVE-2026-32915)
slug: 2026-03-openclaw-sandbox-bypass
description: OpenClaw before 2026.3.11 contains a sandbox boundary bypass vulnerability that allows low-privilege leaf subagents to access the subagents control surface and execute commands with broader tool policies due to insufficient authorization checks, potentially leading to privilege escalation and unauthorized control of sibling processes.
date: "2026-03-29T13:16:59Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sandbox-escape
  - privilege-escalation
  - cve-2026-32915
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32915
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-4w7m-58cg-cmff
  - https://www.vulncheck.com/advisories/openclaw-sandbox-boundary-bypass-via-subagent-control-surface
rules:
  - title: Detect Suspicious Subagent Control Request
    description: Detects subagent control requests that attempt to access resources outside their intended sandbox, indicating a potential sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
  - title: Detect Subagent Terminating Sibling Runs
    description: Detects subagents attempting to terminate sibling runs, which could be a sign of exploitation of CVE-2026-32915.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - impact
    data_sources:
      - application
      - openclaw
rules_count: 2
---

CVE-2026-32915 describes a critical sandbox escape vulnerability affecting OpenClaw versions prior to 2026.3.11. The flaw resides in the insufficient authorization checks implemented on subagent control requests. A low-privilege sandboxed leaf worker can exploit this to bypass the intended sandbox boundaries and access the subagents control surface. This allows the attacker to resolve requests against the parent requester scope, instead of being limited to their own session tree. This…
