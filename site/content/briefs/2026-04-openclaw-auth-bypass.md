---
title: OpenClaw Authorization Bypass Vulnerability (CVE-2026-41299)
slug: 2026-04-openclaw-auth-bypass
description: OpenClaw before 2026.3.28 contains an authorization bypass vulnerability in the chat.send gateway method that allows authenticated operator clients to spoof ACP identity labels and inject reserved provenance fields, leading to potential privilege escalation.
date: "2026-04-21T00:16:30Z"
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-41299
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41299
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-6xg4-82hv-cp6f
  - https://www.vulncheck.com/advisories/openclaw-client-identity-spoofing-in-chat-send-gateway-provenance-guard
rules:
  - title: Detect OpenClaw ACP Identity Spoofing via WebSocket
    description: Detects potential ACP identity spoofing attempts during WebSocket handshake by monitoring client metadata for suspicious patterns related to reserved provenance fields.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Chat Send Gateway Abuse
    description: Detects abuse of the chat.send gateway by monitoring for unusual message origins or content patterns indicative of exploitation.
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

OpenClaw, a chat application, is vulnerable to an authorization bypass (CVE-2026-41299) affecting versions prior to 2026.3.28. This vulnerability resides in the `chat.send` gateway method, where access control policies (ACP) are enforced based on client-provided metadata obtained during the WebSocket handshake. Instead of relying on verified authorization states, the system trusts self-declared metadata, enabling malicious authenticated operator clients to impersonate ACP identities and inject…
