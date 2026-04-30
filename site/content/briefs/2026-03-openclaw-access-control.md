---
title: OpenClaw Insufficient Access Control Vulnerability (CVE-2026-32914)
slug: 2026-03-openclaw-access-control
description: OpenClaw before 2026.3.12 contains an insufficient access control vulnerability in the /config and /debug command handlers that allows command-authorized non-owners to access owner-only surfaces, enabling attackers with command authorization to read or modify privileged configuration settings.
date: "2026-03-29T13:16:59Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - insufficient-access-control
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32914
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-r7vr-gr74-94p8
  - https://www.vulncheck.com/advisories/openclaw-insufficient-access-control-in-config-and-debug-endpoints
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect OpenClaw Unauthorized Config Access
    description: Detects attempts to access the /config endpoint in OpenClaw without proper authorization, indicating potential exploitation of CVE-2026-32914.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Unauthorized Debug Access
    description: Detects attempts to access the /debug endpoint in OpenClaw without proper authorization, indicating potential exploitation of CVE-2026-32914.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.3.12 are vulnerable to an insufficient access control issue, designated as CVE-2026-32914. This vulnerability resides in the `/config` and `/debug` command handlers. An attacker who possesses command authorization, but lacks owner privileges, can leverage this flaw to access sensitive owner-only surfaces. The absence of proper owner-level permission checks allows unauthorized users to potentially read or modify privileged configuration settings that should be…
