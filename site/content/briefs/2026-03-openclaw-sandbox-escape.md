---
title: OpenClaw Session Sandbox Escape Vulnerability (CVE-2026-32918)
slug: 2026-03-openclaw-sandbox-escape
description: OpenClaw before 2026.3.11 contains a session sandbox escape vulnerability in the session_status tool, allowing sandboxed subagents to access and modify session data outside their intended scope.
date: "2026-03-29T13:17:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - openclaw
  - sandbox-escape
  - authorization
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32918
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-wcxr-59v9-rxr8
  - https://www.vulncheck.com/advisories/openclaw-session-sandbox-escape-via-session-status-tool
rules:
  - title: Detect OpenClaw Session Key Manipulation
    description: Detects attempts to manipulate sessionKey values, potentially indicating an attempt to exploit CVE-2026-32918.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Persisted Model Overrides Modification
    description: Detects modification of persisted model overrides, potentially indicating an exploit of CVE-2026-32918.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-32918 affects OpenClaw versions prior to 2026.3.11. The vulnerability resides in the `session_status` tool, which is intended to manage sandboxed subagents. However, a flaw allows these sandboxed agents to bypass their intended restrictions and access session data belonging to parent or sibling sessions. An attacker can exploit this by supplying arbitrary `sessionKey` values, enabling them to read and modify sensitive session data, including persisted model overrides, far beyond the…
