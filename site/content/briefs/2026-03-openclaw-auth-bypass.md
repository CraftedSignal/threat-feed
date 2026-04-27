---
title: OpenClaw Authorization Bypass Vulnerability (CVE-2026-32916)
slug: 2026-03-openclaw-auth-bypass
description: OpenClaw versions 2026.3.7 before 2026.3.11 contain an authorization bypass vulnerability allowing unauthenticated remote requests to execute privileged gateway actions via plugin subagent routes.
date: "2026-03-31T12:16:28Z"
severities:
  - critical
tags:
  - authorization-bypass
  - cve-2026-32916
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Denial
cves:
  - id: CVE-2026-32916
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32916
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-xw77-45gv-p728
  - https://www.vulncheck.com/advisories/openclaw-authorization-bypass-in-plugin-subagent-routes-via-synthetic-admin-scopes
ioc_counts:
  email: 1
rules:
  - title: Detect OpenClaw Runtime Subagent Invocation
    description: Detects attempts to invoke the runtime.subagent method in OpenClaw, potentially indicating exploitation of CVE-2026-32916.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Session Deletion Attempt
    description: Detects attempts to delete sessions in OpenClaw, a possible action performed after exploiting CVE-2026-32916.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions 2026.3.7 through 2026.3.10 are susceptible to an authorization bypass vulnerability (CVE-2026-32916). This flaw stems from plugin subagent routes executing gateway methods through a synthetic operator client that possesses overly broad administrative scopes. An attacker can leverage this vulnerability by sending unauthenticated remote requests to plugin-owned routes. These requests can then invoke the `runtime.subagent` method, leading to the execution of privileged gateway…
