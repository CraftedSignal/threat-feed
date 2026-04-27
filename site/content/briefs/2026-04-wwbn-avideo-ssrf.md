---
title: WWBN AVideo SSRF Vulnerability (CVE-2026-41055)
slug: 2026-04-wwbn-avideo-ssrf
description: WWBN AVideo versions 29.0 and below are vulnerable to Server-Side Request Forgery (SSRF) due to an incomplete fix in the LiveLinks proxy, potentially allowing attackers to redirect traffic to internal endpoints.
date: "2026-04-22T12:00:00Z"
severities:
  - high
tags:
  - ssrf
  - avideo
  - cve-2026-41055
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41055
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41055
  - https://github.com/WWBN/AVideo/commit/8d8fc0cadb425835b4861036d589abcea4d78ee8
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious AVideo SSRF Attempt
    description: Detects potential SSRF attempts against AVideo by looking for requests with specific URI patterns indicative of the LiveLinks proxy feature.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Outbound Connection to Private IP Ranges
    description: Detects AVideo making outbound connections to private IP address ranges, potentially indicating SSRF exploitation.
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

WWBN AVideo, an open-source video platform, is vulnerable to Server-Side Request Forgery (SSRF) in versions 29.0 and below. The vulnerability, identified as CVE-2026-41055, stems from an incomplete fix in the LiveLinks proxy. While the fix introduced `isSSRFSafeURL()` validation, it fails to address Time-of-Check Time-of-Use (TOCTOU) vulnerabilities related to DNS rebinding. This flaw allows attackers to bypass the intended SSRF protection by manipulating DNS responses between the validation…
