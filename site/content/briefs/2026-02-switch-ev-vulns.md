---
title: Multiple Vulnerabilities in SWITCH EV Charging Stations
slug: 2026-02-switch-ev-vulns
description: Multiple vulnerabilities in SWITCH EV swtchenergy.com charging stations could allow attackers to impersonate stations, hijack sessions, cause denial of service, and manipulate backend data due to missing authentication, rate limiting issues, session expiration flaws, and exposed credentials.
date: "2026-02-27T12:00:00Z"
severities:
  - critical
tags:
  - electric-vehicle
  - charging-station
  - websocket
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1592
    technique_name: Gather Victim Host Information
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Drive-by Compromise
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-06
ioc_counts:
  domain: 1
rules:
  - title: Detect Unauthenticated OCPP WebSocket Connection
    description: Detects connections to the OCPP WebSocket endpoint without authentication, potentially indicating station impersonation (CVE-2026-27767).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
  - title: Detect Multiple Connections from Same Source to OCPP Port
    description: Detects multiple connection attempts from the same source IP to the OCPP WebSocket port, potentially indicating brute-force attempts or DoS (CVE-2026-25113).
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1498
    data_sources:
      - network_connection
      - suricata
rules_count: 2
---

SWITCH EV's swtchenergy.com charging stations are affected by multiple vulnerabilities that could allow attackers to gain unauthorized access and disrupt services. These vulnerabilities include missing authentication mechanisms, lack of rate limiting on authentication requests, predictable session identifiers, and publicly accessible authentication identifiers. Successful exploitation could lead to station impersonation, session hijacking, denial-of-service attacks, and manipulation of backend…
