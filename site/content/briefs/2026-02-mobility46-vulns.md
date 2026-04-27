---
title: Mobility46 Charging Station Vulnerabilities Allow Unauthorized Control and Disruption
slug: 2026-02-mobility46-vulns
description: Multiple vulnerabilities in Mobility46 charging stations allow attackers to gain unauthorized administrative control or disrupt charging services through missing authentication, improper authentication restrictions, insufficient session expiration, and exposed credentials.
date: "2026-02-27T12:00:00Z"
severities:
  - critical
tags:
  - mobility46
  - charging-station
  - vulnerability
  - ics
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-08
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27028
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26305
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27647
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22878
ioc_counts:
  domain: 1
rules:
  - title: Detect Unauthenticated WebSocket Connection to Mobility46 Charging Station
    description: Detects WebSocket connections to Mobility46 charging stations without proper authentication, potentially indicating unauthorized access attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Excessive Authentication Attempts to Mobility46 Charging Station
    description: Detects a high number of failed authentication attempts to Mobility46 charging stations, potentially indicating a brute-force or denial-of-service attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Mobility46 charging stations are affected by multiple vulnerabilities that could allow attackers to gain unauthorized administrative control or disrupt charging services. These vulnerabilities, identified in all versions of mobility46.se, include missing authentication for critical functions (CVE-2026-27028), improper restriction of excessive authentication attempts (CVE-2026-26305), insufficient session expiration (CVE-2026-27647), and insufficiently protected credentials (CVE-2026-22878)…
