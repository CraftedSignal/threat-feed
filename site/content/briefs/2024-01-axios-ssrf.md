---
title: Axios NO_PROXY Hostname Normalization Bypass Leads to SSRF
slug: 2024-01-axios-ssrf
description: Axios is vulnerable to a NO_PROXY hostname normalization bypass leading to SSRF, where requests to loopback addresses like `localhost.` or `[::1]` bypass `NO_PROXY` rules, allowing attackers to force requests through a proxy and potentially exfiltrate sensitive data.
date: "2026-04-09T17:32:19Z"
severities:
  - critical
tags:
  - ssrf
  - no_proxy
  - axios
  - hostname_normalization
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-62718
references:
  - https://github.com/advisories/GHSA-3p68-rc4w-qgx5
  - https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
  - https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2
rules:
  - title: Detect Axios SSRF via NO_PROXY Bypass
    description: Detects SSRF attempts exploiting Axios NO_PROXY bypass via hostname normalization issues (trailing dots or IPv6 brackets).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Axios SSRF via NO_PROXY Bypass (HTTP Host Header)
    description: Detects SSRF attempts exploiting Axios NO_PROXY bypass by checking the HTTP Host header for loopback addresses with trailing dots or IPv6 brackets.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Axios, a popular HTTP client for Node.js, is susceptible to a NO_PROXY bypass vulnerability due to incorrect hostname normalization. This flaw, confirmed in version 1.12.2 and affecting all versions prior to 1.15.0, arises from the application's failure to properly handle hostnames with trailing dots (e.g., `localhost.`) or IPv6 literals (e.g., `[::1]`) when evaluating `NO_PROXY` rules.  Instead of performing normalization as recommended by RFC standards, Axios conducts literal string…
