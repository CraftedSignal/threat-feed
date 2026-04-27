---
title: ChatGPTNextWeb NextChat Server-Side Request Forgery Vulnerability
slug: 2026-04-nextchat-ssrf
description: A server-side request forgery (SSRF) vulnerability in ChatGPTNextWeb NextChat up to version 2.16.1 allows remote attackers to manipulate the proxyHandler function, potentially leading to unauthorized internal resource access.
date: "2026-04-28T12:00:00Z"
severities:
  - medium
tags:
  - ssrf
  - cve-2026-7177
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
  - id: CVE-2026-7177
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7177
  - https://gist.github.com/YLChen-007/da6b00024f5b7e1d4fa0658c19b77fbf
  - https://github.com/ChatGPTNextWeb/NextChat/
  - https://github.com/ChatGPTNextWeb/NextChat/issues/6742
  - https://vuldb.com/submit/797645
  - https://vuldb.com/vuln/359779
  - https://vuldb.com/vuln/359779/cti
rules:
  - title: Detect SSRF Attempts in NextChat via API Endpoint
    description: Detects potential SSRF attempts by monitoring requests to the NextChat API endpoint with suspicious URL encoded characters.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SSRF Attempts in NextChat via API Endpoint - Suspicious Path Traversal
    description: Detects potential SSRF attempts by monitoring requests to the NextChat API endpoint with suspicious path traversal characters.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-7177, affects ChatGPTNextWeb NextChat up to version 2.16.1. The vulnerability resides within the `proxyHandler` function in the `app/api/[provider]/[...path]/route.ts` file. Publicly available exploits demonstrate that a remote attacker can manipulate this function to make unauthorized requests to internal resources. The project maintainers were notified, but have not yet responded to the issue, increasing the risk of…
