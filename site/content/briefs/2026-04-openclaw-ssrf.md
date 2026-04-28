---
title: OpenClaw Server-Side Request Forgery Vulnerability (CVE-2026-41297)
slug: 2026-04-openclaw-ssrf
description: OpenClaw before 2026.3.31 is vulnerable to server-side request forgery (SSRF) in the marketplace plugin download functionality, allowing attackers to access internal resources by exploiting unvalidated redirects via the marketplace.ts module.
date: "2026-04-21T00:16:30Z"
severities:
  - high
tags:
  - ssrf
  - cve-2026-41297
  - openclaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41297
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41297
  - https://github.com/openclaw/openclaw/commit/2ce44ca6a1302b166a128abbd78f72114f2f4f52
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-vjx8-8p7h-82gr
  - https://www.vulncheck.com/advisories/openclaw-server-side-request-forgery-via-marketplace-plugin-download-redirect
rules:
  - title: Detect OpenClaw SSRF Attempt via HTTP Redirect
    description: Detects potential SSRF attempts in OpenClaw by monitoring HTTP traffic for suspicious redirects to internal or unexpected external IPs or domains.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1021.001
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw SSRF Attempt via DNS Query to Internal Domain
    description: Detects potential SSRF attempts in OpenClaw by monitoring DNS queries for internal domains.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1021.001
      - T1190
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

OpenClaw before version 2026.3.31 contains a server-side request forgery (SSRF) vulnerability in its marketplace plugin download functionality. This flaw, identified as CVE-2026-41297, allows remote attackers to access internal resources by exploiting unvalidated redirects. The issue lies within the `marketplace.ts` module, which fails to properly restrict redirect destinations during archive downloads. An attacker can manipulate the download process to redirect requests to arbitrary internal…
