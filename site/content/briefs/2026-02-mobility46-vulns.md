---
title: Mobility46 Charging Station Vulnerabilities Allow Unauthorized Control and Disruption
slug: 2026-02-mobility46-vulns
description: Multiple vulnerabilities in Mobility46 charging stations allow attackers to gain unauthorized administrative control or disrupt charging services through missing authentication, improper authentication restrictions, insufficient session expiration, and exposed credentials.
date: "2026-02-27T12:00:00Z"
type: coverage
types:
  - coverage
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
iocs:
  - type: domain
    value: mobility46.se
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

Mobility46 charging stations are affected by multiple vulnerabilities that could allow attackers to gain unauthorized administrative control or disrupt charging services. These vulnerabilities, identified in all versions of mobility46.se, include missing authentication for critical functions (CVE-2026-27028), improper restriction of excessive authentication attempts (CVE-2026-26305), insufficient session expiration (CVE-2026-27647), and insufficiently protected credentials (CVE-2026-22878). Exploitation could lead to privilege escalation, unauthorized control of charging infrastructure, corruption of charging network data, and denial-of-service conditions. Mobility46 did not respond to CISA's request for coordination. These charging stations are deployed worldwide across the energy and transportation sectors.

## Attack Chain

1.  Attacker identifies a Mobility46 charging station's identifier via publicly accessible web-based mapping platforms due to insufficient credential protection (CVE-2026-22878).
2.  Attacker connects to the charging station's OCPP WebSocket endpoint using the discovered charging station identifier, exploiting the lack of authentication mechanisms (CVE-2026-27028).
3.  Attacker issues unauthorized OCPP commands to the charging station, impersonating a legitimate charger due to missing authentication for critical functions (CVE-2026-27028).
4.  Alternatively, the attacker overwhelms the WebSocket API with authentication requests, exploiting the lack of rate limiting and causing a denial-of-service condition (CVE-2026-26305).
5.  Attacker hijacks or shadows a legitimate charging station session by establishing a new connection using the same session identifier, as multiple endpoints are allowed per session (CVE-2026-27647).
6.  The attacker receives backend commands intended for the legitimate charging station, gaining unauthorized control (CVE-2026-27647).
7.  Attacker manipulates charging parameters, disrupts charging services, or corrupts charging network data reported to the backend.
8.  The final objective is to gain unauthorized control of charging infrastructure and disrupt charging services or cause financial and reputational damage.

## Impact

Successful exploitation of these vulnerabilities could enable attackers to gain unauthorized administrative control over vulnerable charging stations, leading to manipulation of charging parameters and disruption of services. Organizations in the energy and transportation sectors are affected worldwide. The lack of authentication and session management could allow attackers to cause denial-of-service conditions, potentially affecting numerous charging stations simultaneously. This could lead to significant financial losses, reputational damage, and disruption of critical infrastructure.

## Recommendation

*   Monitor network connections for unusual WebSocket traffic patterns originating from or directed towards the domain mobility46.se to detect potential exploitation attempts (IOC: mobility46.se).
*   Deploy the Sigma rule "Detect Unauthenticated WebSocket Connection to Mobility46 Charging Station" to identify connections lacking proper authentication. Enable network connection logging for WebSocket traffic (Sigma Rule).
*   Apply rate limiting measures to the WebSocket API endpoints to mitigate potential denial-of-service attacks resulting from excessive authentication attempts as described in CVE-2026-26305.
*   Implement robust authentication mechanisms for all WebSocket endpoints to prevent unauthorized station impersonation and data manipulation, addressing CVE-2026-27028.
*   Investigate and remediate the exposure of charging station authentication identifiers on web-based mapping platforms to prevent unauthorized access, addressing CVE-2026-22878.
