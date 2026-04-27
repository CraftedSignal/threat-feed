---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-35669)
slug: 2026-04-openclaw-privesc
description: OpenClaw before 2026.3.25 contains a privilege escalation vulnerability in gateway-authenticated plugin HTTP routes due to incorrect scope minting, allowing attackers to gain elevated privileges and perform unauthorized administrative actions.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - openclaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35669
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35669
  - https://github.com/openclaw/openclaw/commit/ec2dbcff9afd8a52e00de054b506c91726d9fbbe
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-qm2m-28pf-hgjw
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-gateway-plugin-http-authentication-scope
rules:
  - title: Detect Suspicious OpenClaw Admin Scope Minting
    description: Detects potential exploitation of OpenClaw CVE-2026-35669 by monitoring for requests where admin scope is assigned incorrectly.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Administrative Actions After Privilege Escalation
    description: Detects potential administrative actions after privilege escalation in OpenClaw
    platform: sigma
    severity: medium
    tactics:
      - impact
      - privilege_escalation
    techniques:
      - T1068
      - T1489
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a yet-to-be-determined software application, is susceptible to a privilege escalation vulnerability (CVE-2026-35669) affecting versions prior to 2026.3.25. The vulnerability resides in gateway-authenticated plugin HTTP routes, where the system incorrectly assigns `operator.admin` runtime scope, irrespective of the scopes granted to the caller. This flaw enables attackers to bypass intended scope boundaries, potentially leading to the execution of unauthorized administrative tasks. The…
