---
title: OpenClaw Authentication Bypass in Remote Onboarding
slug: 2026-04-openclaw-auth-bypass
description: OpenClaw before 2026.3.28 contains an authentication bypass vulnerability (CVE-2026-41342) in the remote onboarding component, allowing attackers to spoof discovery endpoints and capture gateway credentials or traffic.
date: "2024-01-03T12:00:00Z"
severities:
  - high
tags:
  - authentication bypass
  - remote onboarding
  - credential theft
  - cve-2026-41342
vendors:
  - openclaw
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-41342
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41342
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-3cw3-5vxw-g2h3
  - https://www.vulncheck.com/advisories/openclaw-unauthenticated-discovery-endpoint-credential-exfiltration-via-remote-onboarding
rules:
  - title: Detect Connection to Suspicious Onboarding Discovery Endpoint
    description: Detects connections to unusual or potentially malicious discovery endpoints during remote onboarding, indicating possible spoofing attempts related to CVE-2026-41342.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - network_connection
      - windows
  - title: Detect OpenClaw Process Connecting to Non-Standard Ports
    description: This rule identifies OpenClaw processes establishing network connections to ports commonly associated with malicious activity, potentially indicating exploitation or command and control.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

OpenClaw, a software solution, is vulnerable to an authentication bypass flaw in versions prior to 2026.3.28. Specifically, the remote onboarding component persists unauthenticated discovery endpoints without requiring explicit trust confirmation. This vulnerability, identified as CVE-2026-41342, enables a threat actor to spoof legitimate discovery endpoints. By doing so, attackers can redirect the onboarding process toward malicious gateways under their control. This redirection allows the…
