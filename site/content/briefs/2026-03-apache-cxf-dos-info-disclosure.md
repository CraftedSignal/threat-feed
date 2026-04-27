---
title: Apache CXF Vulnerability Allows DoS and Information Disclosure
slug: 2026-03-apache-cxf-dos-info-disclosure
description: An anonymous remote attacker can exploit a vulnerability in Apache CXF to perform a denial of service attack and disclose sensitive information.
date: "2026-03-25T12:00:00Z"
severities:
  - high
tags:
  - apache-cxf
  - denial-of-service
  - information-disclosure
  - webserver
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-1574
rules:
  - title: Detect Suspicious Apache CXF Request
    description: Detects suspicious requests to Apache CXF endpoints that may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
      - discovery
    data_sources:
      - webserver
      - linux
  - title: Detect Apache CXF Service Unavailable
    description: Detects service unavailable responses from Apache CXF endpoints, potentially indicating a DoS attack.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists in Apache CXF that could allow an anonymous, remote attacker to conduct a denial of service (DoS) attack and disclose sensitive information. The specific versions affected are not detailed in this advisory. The attacker exploits an unspecified weakness within Apache CXF's processing capabilities. Successful exploitation leads to service disruption and potentially exposes confidential data handled by the affected Apache CXF instance. This vulnerability poses a significant…
