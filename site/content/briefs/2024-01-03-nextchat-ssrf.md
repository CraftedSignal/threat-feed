---
title: ChatGPTNextWeb NextChat SSRF Vulnerability (CVE-2026-7178)
slug: 2024-01-03-nextchat-ssrf
description: ChatGPTNextWeb NextChat versions up to 2.16.1 are vulnerable to server-side request forgery (SSRF) due to improper input validation in the storeUrl function, allowing remote attackers to potentially access internal resources or conduct other malicious activities.
date: "2024-01-03T12:00:00Z"
severities:
  - high
exploited: true
tags:
  - ssrf
  - cve
  - vulnerability
  - web-application
vendors:
  - ChatGPTNextWeb
products:
  - NextChat
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7178
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7178
rules:
  - title: NextChat SSRF Attempt
    description: Detects potential SSRF attempts against ChatGPTNextWeb NextChat by monitoring requests to the /api/artifacts endpoint with suspicious ID parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: NextChat Internal IP Access via SSRF
    description: Detects potential SSRF abuse by monitoring access to private IP ranges from the NextChat server.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-7178, affects ChatGPTNextWeb NextChat versions up to 2.16.1. The vulnerability resides in the `storeUrl` function within the `app/api/artifacts/route.ts` file, specifically related to the Artifacts Endpoint component. An attacker can manipulate the `ID` argument to force the server to make requests to arbitrary internal or external resources. This issue was reported to the project maintainers but remains unpatched. The…
