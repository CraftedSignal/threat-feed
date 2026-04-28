---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-41329)
slug: 2026-04-openclaw-privesc
description: A critical privilege escalation vulnerability (CVE-2026-41329) in OpenClaw versions up to 2026.3.28 allows attackers to bypass sandbox restrictions via improper context validation, leading to potential data breaches and system compromise.
date: "2026-04-21T15:02:58Z"
severities:
  - critical
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
  - id: CVE-2026-41329
    cvss: 9.9
references:
  - https://ccb.belgium.be/advisories/warning-privilege-escalation-openclaw-patch-immediately
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-g5cg-8x5w-7jpm
rules:
  - title: Detect Suspicious OpenClaw Heartbeat Activity
    description: Detects potential exploitation of CVE-2026-41329 by monitoring for unusual heartbeat requests to OpenClaw instances.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Version <= 2026.3.28 in User-Agent
    description: Detects connections from OpenClaw clients with a User-Agent string indicating a vulnerable version.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-41329, has been identified in OpenClaw versions up to and including 2026.3.28. OpenClaw is an open-source, self-hosted AI agent platform designed for workflow automation, event-driven processing, and task orchestration, commonly deployed in internal environments. The vulnerability stems from improper context validation during heartbeat processing, enabling attackers to exploit context inheritance and manipulate the `senderIsOwner` parameter. This…
