---
title: Multiple Vulnerabilities in Chargemap Charging Stations
slug: 2026-02-chargemap-vulns
description: Unauthenticated attackers can exploit multiple vulnerabilities in Chargemap's charging stations, including missing authentication, improper authentication attempt restrictions, insufficient session expiration, and unprotected credentials, potentially leading to unauthorized control and denial-of-service.
date: "2026-02-26T12:00:00Z"
severities:
  - critical
tags:
  - ics
  - ot
  - vulnerability
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.004
    technique_name: 'Endpoint Denial of Service: Application Exhaustion'
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-05
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-057-05.json
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25851
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20792
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25711
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20791
ioc_counts:
  domain: 1
rules:
  - title: Detect Unauthenticated OCPP WebSocket Connections
    description: Detects unauthenticated connections to OCPP WebSocket endpoints, potentially indicating exploitation of CVE-2026-25851.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1595.002
    data_sources:
      - network_connection
      - zeek
  - title: Detect Excessive Authentication Attempts to WebSocket API
    description: Detects a high volume of authentication attempts to the WebSocket API, potentially indicating a brute-force or denial-of-service attack exploiting CVE-2026-20792.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - suricata
rules_count: 2
---

Chargemap chargemap.com is affected by multiple critical vulnerabilities that could allow attackers to gain unauthorized administrative control over charging stations or disrupt charging services. These vulnerabilities include missing authentication for critical functions (CVE-2026-25851), improper restriction of excessive authentication attempts (CVE-2026-20792), insufficient session expiration (CVE-2026-25711), and insufficiently protected credentials (CVE-2026-20791). The vulnerabilities…
