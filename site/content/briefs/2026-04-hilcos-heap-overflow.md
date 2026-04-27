---
title: Hirschmann HiLCOS Web Interface Heap Overflow Vulnerability (CVE-2024-14033)
slug: 2026-04-hilcos-heap-overflow
description: A heap overflow vulnerability in the HiLCOS web interface of Hirschmann Industrial IT products (CVE-2024-14033) allows unauthenticated remote attackers to cause a denial-of-service condition by sending specially crafted requests, leading to device crashes and service disruption, particularly when the Public Spot functionality is enabled.
date: "2026-04-02T21:16:39Z"
severities:
  - high
tags:
  - cve-2024-14033
  - denial-of-service
  - heap-overflow
  - hilcos
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2024-14033
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-14033
  - https://assets.belden.com/m/774d24c02be5c220/original/Belden_Security_Bulletin_BSECV-2024-16.pdf
  - https://ssd-disclosure.com/ssd-advisory-lancom-lcos-heap-overflow/
rules:
  - title: Detect Suspicious HiLCOS Web Requests
    description: Detects potentially malicious HTTP requests targeting the HiLCOS web interface that may indicate exploitation attempts of CVE-2024-14033.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of Web Requests to HiLCOS Interface
    description: Detects a potential DoS attack against the HiLCOS interface based on a high volume of requests from a single source IP address.
    platform: sigma
    severity: low
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Hirschmann Industrial IT products are susceptible to a heap overflow vulnerability identified as CVE-2024-14033 within the HiLCOS web interface. This vulnerability enables unauthenticated remote attackers to trigger a denial-of-service condition by sending specific, crafted requests to the affected web interface. Successful exploitation of this vulnerability results in the crashing of the targeted device, causing service disruption. The risk is heightened in configurations where the Public Spot…
