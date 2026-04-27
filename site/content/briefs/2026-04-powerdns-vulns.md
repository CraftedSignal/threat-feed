---
title: Multiple Vulnerabilities in PowerDNS
slug: 2026-04-powerdns-vulns
description: Multiple vulnerabilities in PowerDNS could be exploited by an attacker to disclose information, bypass security measures, cause a denial of service, and potentially execute code.
date: "2026-04-01T09:22:02Z"
severities:
  - high
tags:
  - powerdns
  - vulnerability
  - dos
  - information-disclosure
  - code-execution
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0932
rules:
  - title: Detect Potential PowerDNS DoS Attack
    description: Detects potential Denial-of-Service attacks against PowerDNS servers based on high request rates from a single source IP.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - linux
rules_count: 1
---

Multiple vulnerabilities have been identified in PowerDNS, a widely used DNS server software. An unauthenticated remote attacker could exploit these vulnerabilities to achieve a range of malicious outcomes. Successful exploitation could lead to sensitive information disclosure, bypassing of implemented security measures, denial-of-service (DoS) conditions rendering the DNS server unavailable, and potentially arbitrary code execution. The specific versions affected and the precise nature of each…
