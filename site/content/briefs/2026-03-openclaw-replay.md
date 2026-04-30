---
title: OpenClaw Bootstrap Code Replay Vulnerability (CVE-2026-32987)
slug: 2026-03-openclaw-replay
description: OpenClaw before 2026.3.13 is vulnerable to a replay attack during device pairing verification, allowing attackers to repeatedly verify a bootstrap code and escalate privileges to operator.admin.
date: "2026-03-29T13:17:02Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - replay-attack
  - privilege-escalation
  - device-pairing
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32987
  - https://github.com/openclaw/openclaw/commit/1803d16d5cec970c54b0e1ac46b31b1cbade335c
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-63f5-hhc7-cx6p
  - https://www.vulncheck.com/advisories/openclaw-bootstrap-setup-code-replay-via-device-pairing
ioc_counts:
  email: 1
rules:
  - title: Detect Repeated Bootstrap Code Verification
    description: Detects multiple attempts to verify the same bootstrap code within a short time frame, indicative of a replay attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1068
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Privilege Escalation to operator.admin
    description: Detects successful privilege escalation to operator.admin after bootstrap code verification.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.3.13 contains a vulnerability in the device pairing verification process.  Specifically, the `src/infra/device-bootstrap.ts` file allows bootstrap setup codes to be replayed. This means an attacker can repeatedly use the same valid bootstrap code before it is approved, leading to an escalation of pending pairing scopes. The most critical outcome is privilege escalation to the `operator.admin` level, granting the attacker significant control over the affected system…
