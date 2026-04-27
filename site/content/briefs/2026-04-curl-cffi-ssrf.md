---
title: curl_cffi SSRF Vulnerability via Redirects
slug: 2026-04-curl-cffi-ssrf
description: curl_cffi versions before 0.15.0 are vulnerable to server-side request forgery (SSRF) due to unrestricted redirects to internal IP ranges, potentially enabling access to sensitive internal resources and cloud metadata.
date: "2026-04-03T21:36:44Z"
severities:
  - high
tags:
  - ssrf
  - curl_cffi
  - cloud
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-68616
    cvss: 7.5
    epss: 0.00061
references:
  - https://github.com/advisories/GHSA-qw2m-4pqf-rmpp
ioc_counts:
  domain: 1
  ip: 2
rules:
  - title: Detect curl_cffi Process Accessing Metadata Endpoint
    description: Detects processes using curl_cffi making network connections to the cloud metadata endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect HTTP Redirects to Internal IP Ranges
    description: Detects HTTP 302 redirects to internal IP ranges, indicating a potential SSRF attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The curl_cffi library, a Python binding for libcurl, is susceptible to a server-side request forgery (SSRF) vulnerability in versions prior to 0.15.0. This flaw stems from the library's unrestricted handling of redirects, allowing attacker-controlled URLs to redirect requests to internal IP ranges and services. An attacker can exploit this behavior to access sensitive information such as cloud metadata or bypass network controls. The vulnerability is triggered because curl_cffi automatically…
