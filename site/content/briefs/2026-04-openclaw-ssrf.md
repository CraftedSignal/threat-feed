---
title: OpenClaw SSRF Guard Bypass via IPv6 Special Use Ranges (CVE-2026-41361)
slug: 2026-04-openclaw-ssrf
description: OpenClaw before 2026.3.28 is vulnerable to a Server-Side Request Forgery (SSRF) guard bypass due to its failure to block four IPv6 special-use ranges, allowing attackers to craft URLs targeting internal or non-routable IPv6 addresses.
date: "2026-04-24T12:00:00Z"
severities:
  - medium
tags:
  - ssrf
  - cve-2026-41361
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery (SSRF)
cves:
  - id: CVE-2026-41361
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41361
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-g86v-f9qv-rh6m
  - https://www.vulncheck.com/advisories/openclaw-ssrf-guard-bypass-via-ipv6-special-use-ranges
rules:
  - title: Detect SSRF Attempt via IPv6 Special-Use Range
    description: Detects potential SSRF attempts by identifying HTTP requests containing IPv6 addresses from known special-use ranges.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
  - title: Detect SSRF Attempt via IPv6 Special-Use Range in POST Data
    description: Detects potential SSRF attempts by identifying HTTP POST requests containing IPv6 addresses from known special-use ranges in the request body.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.3.28 is susceptible to a Server-Side Request Forgery (SSRF) guard bypass vulnerability, identified as CVE-2026-41361. This flaw stems from the software's inability to properly block four specific IPv6 special-use ranges. By exploiting this vulnerability, attackers can craft malicious URLs that target internal or non-routable IPv6 addresses, effectively circumventing SSRF protections. This can allow attackers to probe internal services, access sensitive data, or…
