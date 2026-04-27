---
title: Internet Systems Consortium BIND Vulnerabilities Leading to Denial of Service
slug: 2026-03-isc-bind-dos
description: Multiple vulnerabilities in Internet Systems Consortium BIND can be exploited by a remote attacker to conduct a denial of service attack or bypass security measures.
date: "2026-03-30T10:14:09Z"
severities:
  - high
tags:
  - dns
  - denial-of-service
  - bind
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0863
rules:
  - title: Detect High DNS Query Rate to a Single Server
    description: Detects a high rate of DNS queries to a single server, potentially indicating a denial-of-service attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - dns_query
      - linux
  - title: Detect DNS Query Flood from Single Source IP
    description: Detects a flood of DNS queries originating from a single source IP address, potentially indicating a denial-of-service attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - dns_query
      - linux
rules_count: 2
---

The Internet Systems Consortium (ISC) BIND (Berkeley Internet Name Domain) is a widely used open-source DNS server software. Multiple vulnerabilities exist within BIND that can be exploited by remote attackers. An unauthenticated attacker can leverage these flaws to conduct denial-of-service (DoS) attacks, disrupting DNS resolution services. The specific versions affected are not specified in the provided source, but administrators should consult ISC's security advisories for detailed version…
