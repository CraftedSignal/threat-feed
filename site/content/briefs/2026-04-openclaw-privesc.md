---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-35663)
slug: 2026-04-openclaw-privesc
description: OpenClaw before 2026.3.25 contains a privilege escalation vulnerability (CVE-2026-35663) that allows non-admin operators to gain unauthorized administrative privileges by self-requesting broader scopes during backend reconnect and bypassing pairing requirements.
date: "2026-04-10T17:17:08Z"
severities:
  - high
tags:
  - privilege-escalation
  - cve-2026-35663
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35663
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35663
  - https://github.com/openclaw/openclaw/commit/d3d8e316bd819d3c7e34253aeb7eccb2510f5f48
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-9hjh-fr4f-gxc4
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-backend-reconnect-scope-self-claim
rules:
  - title: Detect OpenClaw Privilege Escalation
    description: Detects attempts to escalate privileges in OpenClaw by requesting the operator.admin scope during backend reconnect.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Backend Reconnect Scope Modification
    description: Detects modifications to the scope parameter during an OpenClaw backend reconnect, potentially indicating privilege escalation attempts.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a yet-to-be-identified application, is vulnerable to a privilege escalation flaw (CVE-2026-35663) in versions prior to 2026.3.25. The vulnerability allows a non-administrative operator to escalate their privileges to that of an administrator. This is achieved by manipulating the backend reconnect process to self-request broader scopes, specifically the `operator.admin` scope. The attacker bypasses the standard pairing requirements, allowing them to authenticate as an administrator…
