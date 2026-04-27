---
title: CVE-2026-33096 HTTP.sys Out-of-Bounds Read Denial-of-Service
slug: 2026-04-http-sys-dos
description: An unauthenticated, remote attacker can exploit an out-of-bounds read vulnerability (CVE-2026-33096) in Windows HTTP.sys to cause a denial-of-service condition.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-33096
  - denial-of-service
  - windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-33096
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33096
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33096
rules:
  - title: Detect Suspicious HTTP Request Length (Potential HTTP.sys DoS)
    description: Detects HTTP requests with unusually large Content-Length headers, potentially indicating a DoS attempt targeting HTTP.sys
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - windows
  - title: Detect High Volume of Requests to Web Server from Single IP
    description: Detects a high volume of requests to a web server from a single IP address within a short timeframe, potentially indicating a DoS attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - windows
rules_count: 2
---

CVE-2026-33096 describes an out-of-bounds read vulnerability affecting the Windows HTTP.sys component. This vulnerability allows an unauthenticated attacker to remotely trigger a denial-of-service (DoS) condition on a vulnerable system. HTTP.sys is a core component of the Windows operating system that handles HTTP requests; therefore, a successful exploit can impact any service relying on HTTP.sys, including web servers and other network applications. The vulnerability was publicly disclosed on…
