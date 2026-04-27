---
title: Suricata HTTP2 Continuation Frame Flooding Denial of Service (CVE-2026-31935)
slug: 2026-04-suricata-http2-dos
description: A denial of service vulnerability, CVE-2026-31935, exists in Suricata versions prior to 7.0.15 and 8.0.4, where flooding the system with crafted HTTP2 continuation frames leads to memory exhaustion and process termination.
date: "2026-04-02T15:16:37Z"
severities:
  - medium
tags:
  - cve
  - dos
  - http2
  - suricata
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-31935
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31935
  - https://github.com/OISF/suricata/security/advisories/GHSA-vxrp-5pg7-7v4x
  - https://redmine.openinfosecfoundation.org/issues/8289
rules:
  - title: Detect Suspicious HTTP2 Continuation Frame Flooding
    description: Detects potential denial-of-service attempts by monitoring for an excessive number of HTTP2 continuation frames within a short timeframe.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Suricata Process Memory Usage Spike
    description: Detects a sudden increase in memory usage by the Suricata process, potentially indicating a memory exhaustion attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-31935 describes a denial-of-service vulnerability affecting Suricata, a network IDS, IPS, and NSM engine. The vulnerability lies in the processing of HTTP2 continuation frames. Versions prior to 7.0.15 and 8.0.4 are susceptible to memory exhaustion when flooded with maliciously crafted HTTP2 continuation frames. This excessive memory consumption typically results in the operating system shutting down the Suricata process to prevent system instability. The vulnerability was reported and…
