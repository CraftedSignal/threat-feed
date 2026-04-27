---
title: OpenClaw Insufficient Access Control in Gateway Agent Session Reset (CVE-2026-35660)
slug: 2026-04-openclaw-reset-vuln
description: OpenClaw before 2026.3.23 contains an insufficient access control vulnerability in the Gateway agent /reset endpoint that allows callers with operator.write permission to reset admin sessions by invoking /reset or /new messages with an explicit sessionKey, bypassing operator.admin requirements.
date: "2026-04-10T17:50:21Z"
severities:
  - high
tags:
  - cve-2026-35660
  - openclaw
  - access-control
  - privilege-escalation
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-35660
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35660
  - https://github.com/openclaw/openclaw/commit/50f6a2f136fed85b58548a38f7a3dbb98d2cd1a0
  - https://github.com/openclaw/openclaw/commit/630f1479c44f78484dfa21bb407cbe6f171dac87
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-wq58-2pvg-5h4f
  - https://www.vulncheck.com/advisories/openclaw-insufficient-access-control-in-gateway-agent-session-reset
ioc_counts:
  email: 1
  url: 4
rules:
  - title: Detect OpenClaw Session Reset Attempt
    description: Detects attempts to reset admin sessions in OpenClaw via the /reset endpoint, exploiting CVE-2026-35660.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw New Session with Admin Key
    description: Detects attempts to create a new session using an existing admin sessionKey, potentially bypassing authentication.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a yet-to-be-defined application, suffers from an insufficient access control vulnerability (CVE-2026-35660) affecting versions prior to 2026.3.23. The vulnerability exists within the Gateway agent's `/reset` endpoint.  An attacker possessing `operator.write` permissions can exploit this flaw to reset administrative sessions, circumventing the intended `operator.admin` requirement.  Specifically, the vulnerability allows attackers to invoke `/reset` or `/new` messages including an…
