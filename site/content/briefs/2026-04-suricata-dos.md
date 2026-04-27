---
title: Suricata DoS Vulnerability (CVE-2026-31933)
slug: 2026-04-suricata-dos
description: Specially crafted network traffic can cause Suricata to slow down, leading to a denial-of-service condition in versions prior to 7.0.15 and 8.0.4, as identified by CVE-2026-31933.
date: "2026-04-02T14:16:28Z"
severities:
  - medium
tags:
  - dos
  - suricata
  - cve-2026-31933
  - network
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-31933
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31933
  - https://github.com/OISF/suricata/security/advisories/GHSA-hvp5-gpr6-j4gp
  - https://redmine.openinfosecfoundation.org/issues/8272
ioc_counts:
  email: 1
rules:
  - title: Detect High Packet Rate
    description: Detects a high rate of network packets, potentially indicating a denial-of-service attack
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - suricata
  - title: Detect Multiple Connections from Single Source
    description: Detects a high number of connections originating from a single source IP, indicative of a DoS
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - suricata
rules_count: 2
---

Suricata, a network IDS, IPS, and NSM engine, is susceptible to a denial-of-service vulnerability (CVE-2026-31933) affecting versions prior to 7.0.15 and 8.0.4. This flaw arises from inefficient algorithmic complexity (CWE-407), where specially crafted network traffic can induce a significant slowdown in Suricata's processing, particularly impacting its performance in IDS mode. An attacker can exploit this vulnerability by sending malicious network packets, potentially causing the Suricata…
