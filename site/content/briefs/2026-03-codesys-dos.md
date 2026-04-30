---
title: CODESYS Control Runtime System Audit Log DoS Vulnerability (CVE-2026-3509)
slug: 2026-03-codesys-dos
description: An unauthenticated remote attacker can exploit CVE-2026-3509 in the CODESYS Control runtime system to control the format string of messages processed by the Audit Log, leading to a denial-of-service (DoS) condition.
date: "2026-03-25T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - codesys
  - dos
  - cve-2026-3509
  - ics
  - ot
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3509
  - https://certvde.com/de/advisories/VDE-2026-018
rules:
  - title: Detect Suspicious Network Requests to CODESYS Audit Log
    description: Detects network requests to CODESYS Control runtime system that might exploit the format string vulnerability (CVE-2026-3509).
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect CODESYS Process Crash
    description: Detects a CODESYS process crash which may indicate a denial of service via CVE-2026-3509
    platform: sigma
    severity: critical
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-3509 describes a format string vulnerability within the Audit Log of the CODESYS Control runtime system. This vulnerability allows an unauthenticated remote attacker to influence the format string of messages processed by the affected system. Successful exploitation of this vulnerability results in a denial-of-service (DoS) condition, impacting the availability of the CODESYS Control runtime system. The vulnerability was reported on March 24, 2026. CODESYS is a popular development…
