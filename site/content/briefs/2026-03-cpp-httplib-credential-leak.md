---
title: cpp-httplib Vulnerability Leads to Credential Leakage via HTTP Redirects
slug: 2026-03-cpp-httplib-credential-leak
description: The cpp-httplib library prior to version 0.39.0 forwards stored authentication credentials to arbitrary hosts via HTTP redirects, potentially exposing sensitive information to malicious actors.
date: "2026-03-27T01:16:21Z"
severities:
  - high
tags:
  - cpp-httplib
  - credential-leak
  - cve-2026-33745
  - http-redirect
  - credential-access
  - cross-origin
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33745
rules:
  - title: Detect Outbound HTTP Request with Authorization Header to Unfamiliar Domain
    description: Detects an outbound HTTP request containing an Authorization header to a domain not in a whitelist, which could indicate credential theft via HTTP redirect vulnerability (CVE-2026-33745).
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - network_connection
      - windows
  - title: Detect Process Making Network Connections with Authorization Header Set
    description: Detects a process making network connections where the authorization header is being sent. Requires process creation and network connection logs.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The cpp-httplib library, a C++11 single-file header-only cross platform HTTP/HTTPS library, contains a vulnerability (CVE-2026-33745) in versions prior to 0.39.0. This flaw allows an attacker to potentially steal sensitive credentials by exploiting the library's behavior when handling cross-origin HTTP redirects (301, 302, 307, 308). Specifically, stored Basic Auth, Bearer Token, and Digest Auth credentials are unintentionally forwarded to arbitrary hosts during these redirects. This means a…
