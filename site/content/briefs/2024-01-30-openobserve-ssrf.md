---
title: OpenObserve SSRF via Improper IPv6 Validation
slug: 2024-01-30-openobserve-ssrf
description: OpenObserve versions 0.70.3 and earlier are vulnerable to a server-side request forgery (SSRF) attack due to improper validation of IPv6 addresses in the validate_enrichment_url function, potentially allowing authenticated attackers to access internal services and retrieve sensitive cloud metadata.
date: "2026-04-07T20:16:29Z"
severities:
  - high
tags:
  - ssrf
  - openobserve
  - cloud
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-39361
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39361
ioc_counts:
  ip: 1
rules:
  - title: Detect OpenObserve SSRF Attempt via AWS IMDS Access
    description: Detects network connections from OpenObserve servers to the AWS IMDSv1 endpoint (169.254.169.254), indicating a potential SSRF attempt to steal IAM credentials.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Detect OpenObserve process making outbound connection
    description: Detects outbound connections from OpenObserve processes, which can be used to detect SSRF.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

OpenObserve, a cloud-native observability platform, contains a server-side request forgery (SSRF) vulnerability (CVE-2026-39361) in versions 0.70.3 and earlier. The vulnerability resides in the `validate_enrichment_url` function within `src/handler/http/request/enrichment_table/mod.rs`. This function fails to properly block IPv6 addresses due to the Rust's `url` crate returning IPv6 addresses with surrounding brackets (e.g., "[::1]") instead of without. This allows an authenticated attacker to…
