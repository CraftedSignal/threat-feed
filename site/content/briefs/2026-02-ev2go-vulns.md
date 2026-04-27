---
title: EV2GO Charging Station Vulnerabilities Allow Impersonation and Denial of Service
slug: 2026-02-ev2go-vulns
description: Multiple vulnerabilities in EV2GO charging stations, including missing authentication and session management flaws, could allow attackers to impersonate stations, hijack sessions, and cause denial-of-service conditions.
date: "2026-02-27T10:00:00Z"
severities:
  - critical
tags:
  - ev2go
  - charging-station
  - vulnerability
  - denial-of-service
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-057-04
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24731
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25945
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20895
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22890
ioc_counts:
  domain: 1
rules:
  - title: Detect Unauthorized OCPP Connection
    description: Detects unauthorized connections to the OCPP WebSocket endpoint which lacks proper authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - network_connection
      - windows
  - title: Detect Excessive Authentication Attempts to OCPP WebSocket
    description: Detects a high number of failed or successful authentication attempts to the OCPP WebSocket endpoint, indicating potential brute-force or DoS attacks.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Multiple vulnerabilities have been discovered in EV2GO ev2go.io charging stations. These vulnerabilities, identified as CVE-2026-24731, CVE-2026-25945, CVE-2026-20895, and CVE-2026-22890, relate to missing authentication for critical functions, improper restriction of excessive authentication attempts, insufficient session expiration, and insufficiently protected credentials. Successful exploitation of these flaws could enable attackers to impersonate charging stations, hijack legitimate user…
