---
title: Monetr Lunch Flow SSRF Vulnerability
slug: 2024-05-monetr-ssrf
description: A server-side request forgery (SSRF) vulnerability in Monetr's Lunch Flow integration allows authenticated users on self-hosted instances to send HTTP GET requests to arbitrary URLs, potentially exposing sensitive information.
date: "2024-05-02T12:00:00Z"
severities:
  - medium
tags:
  - ssrf
  - monitr
  - github-advisory
vendors:
  - Monetr
products:
  - Monetr
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-29v9-frvh-c426
ioc_counts:
  url: 1
rules:
  - title: Detect Monetr Lunch Flow Link Creation with Suspicious URL
    description: Detects attempts to create Lunch Flow links with URLs pointing to private IP addresses or cloud metadata endpoints, indicative of SSRF attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Monetr Warning Log for Rejected Lunch Flow API URL
    description: Detects warning logs indicating that a Lunch Flow API URL was rejected because it's not in the configured allowlist.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability was identified in the Lunch Flow integration of Monetr, affecting self-hosted instances. This vulnerability allows any authenticated user to cause the Monetr server to issue HTTP GET requests to arbitrary URLs, with the response body from non-200 upstream responses reflected back in the API error message. The URL validator on the `POST /api/lunch_flow/link` endpoint lacked sufficient filtering, failing to block loopback, RFC1918, link-local, or…
