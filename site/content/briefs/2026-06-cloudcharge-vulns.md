---
title: CloudCharge Vulnerabilities Allow Charging Station Impersonation and DoS
slug: 2026-06-cloudcharge-vulns
description: Multiple vulnerabilities in CloudCharge cloudcharge.se allow attackers to impersonate charging stations, hijack sessions, cause denial of service, and manipulate backend data, impacting energy and transportation sectors.
date: "2026-06-13T12:00:00Z"
severities:
  - critical
tags:
  - cloudcharge
  - ics
  - vulnerability
  - dos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-03
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20781
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25114
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27652
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20733
ioc_counts:
  domain: 1
  url: 1
rules:
  - title: Detect Suspicious CloudCharge WebSocket Connection
    description: Detects network connections to CloudCharge infrastructure from unusual IPs, indicating potential unauthorized access attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - network_connection
      - windows
  - title: Detect CloudCharge Session Hijacking
    description: Detects multiple connections using the same charging station identifier, indicating potential session hijacking.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified in CloudCharge cloudcharge.se, a charging station management platform. These vulnerabilities, including CVE-2026-20781, CVE-2026-25114, CVE-2026-27652, and CVE-2026-20733, could allow attackers to compromise charging stations and backend systems. Specifically, the lack of proper authentication and session management in the WebSocket API enables unauthorized access and control. Given that the vulnerable software is used within the Energy and…
