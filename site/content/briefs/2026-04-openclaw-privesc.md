---
title: OpenClaw Privilege Escalation via chat.send
slug: 2026-04-openclaw-privesc
description: OpenClaw before 2026.3.28 contains a privilege escalation vulnerability (CVE-2026-41371) in chat.send, allowing write-scoped gateway callers to execute admin-only session reset operations by bypassing authorization checks.
date: "2026-04-28T00:16:26Z"
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - CVE-2026-41371
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41371
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41371
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-5r8f-96gm-5j6g
  - https://www.vulncheck.com/advisories/openclaw-privilege-escalation-via-chat-send-reset-command
rules:
  - title: Detect OpenClaw chat.send Privilege Escalation Attempt
    description: Detects attempts to exploit CVE-2026-41371 by monitoring for suspicious chat.send requests that try to trigger session resets.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-41371
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw chat.send Session Rotation
    description: Detects potential session rotation by monitoring for the archiving of prior transcript state in OpenClaw.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-41371
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a chat application, is vulnerable to a privilege escalation flaw (CVE-2026-41371) affecting versions prior to 2026.3.28. This vulnerability resides within the chat.send functionality, where improper authorization checks allow callers with write scope to trigger admin-only session reset operations. This means a low-privileged attacker could potentially manipulate and disrupt chat sessions without requiring administrative privileges, leading to unauthorized actions and potential data…
