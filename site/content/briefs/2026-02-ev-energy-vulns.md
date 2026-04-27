---
title: Multiple Vulnerabilities in EV Energy ev.energy Charging Stations
slug: 2026-02-ev-energy-vulns
description: Multiple vulnerabilities exist in EV Energy ev.energy that could allow an attacker to gain unauthorized administrative control over vulnerable charging stations or disrupt charging services through denial-of-service attacks.
date: "2026-02-26T12:00:00Z"
severities:
  - critical
tags:
  - ev.energy
  - charging-station
  - ics
  - vulnerability
  - dos
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-07
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-057-07.json
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27772
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24445
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26290
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25774
rules:
  - title: Detect Unauthorized OCPP WebSocket Connection
    description: Detects connections to the OCPP WebSocket endpoint without proper authentication, potentially indicating an attacker exploiting CVE-2026-27772.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - zeek
  - title: Detect Excessive Authentication Attempts on OCPP WebSocket API
    description: Detects a high number of authentication requests on the OCPP WebSocket API from a single source, potentially indicating a denial-of-service attack exploiting CVE-2026-24445.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

Multiple vulnerabilities have been identified in EV Energy ev.energy charging stations, potentially allowing attackers to gain unauthorized administrative control or disrupt charging services. The vulnerabilities, detailed in CISA ICS Advisory ICSA-26-057-07, affect all versions of ev.energy. These vulnerabilities include missing authentication for critical functions (CVE-2026-27772), improper restriction of excessive authentication attempts (CVE-2026-24445), insufficient session expiration…
