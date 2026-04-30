---
title: CloudCharge Vulnerabilities Allow Charging Station Impersonation and DoS
slug: 2026-06-cloudcharge-vulns
description: Multiple vulnerabilities in CloudCharge cloudcharge.se allow attackers to impersonate charging stations, hijack sessions, cause denial of service, and manipulate backend data, impacting energy and transportation sectors.
date: "2026-06-13T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cloudcharge
  - ics
  - vulnerability
  - dos
vendors:
  - CloudCharge
products:
  - cloudcharge.se
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
iocs:
  - type: domain
    value: cloudcharge.se
  - type: url
    value: https://cloudcharge.tech/support/contact/
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

Multiple vulnerabilities have been identified in CloudCharge cloudcharge.se, a charging station management platform. These vulnerabilities, including CVE-2026-20781, CVE-2026-25114, CVE-2026-27652, and CVE-2026-20733, could allow attackers to compromise charging stations and backend systems. Specifically, the lack of proper authentication and session management in the WebSocket API enables unauthorized access and control. Given that the vulnerable software is used within the Energy and Transportation Systems sectors worldwide, successful exploitation could disrupt critical infrastructure. The vendor has not responded to coordination requests.

## Attack Chain

1. An attacker identifies a publicly accessible charging station identifier via web-based mapping platforms (CVE-2026-20733).
2. The attacker connects to the OCPP WebSocket endpoint of a CloudCharge charging station using the discovered identifier (CVE-2026-20781).
3. Due to the missing authentication mechanisms, the attacker successfully impersonates a legitimate charger (CVE-2026-20781).
4. The attacker exploits the lack of rate limiting and floods the authentication endpoint with requests, causing a denial-of-service condition by suppressing legitimate charger telemetry (CVE-2026-25114).
5. Alternatively, the attacker exploits the predictable session identifiers and attempts to hijack an existing charging session (CVE-2026-27652).
6. The attacker sends malicious OCPP commands to manipulate charging processes or corrupt charging network data reported to the backend (CVE-2026-20781).
7. The attacker displaces the legitimate charging station's connection, receiving backend commands intended for the original station (CVE-2026-27652).
8. The ultimate objective is to disrupt charging services, manipulate billing information, or gain persistent access to the charging infrastructure backend.

## Impact

Successful exploitation of these vulnerabilities could have significant consequences, particularly in the Energy and Transportation Systems sectors. Attackers could disrupt electric vehicle charging services, leading to widespread outages and transportation delays. Compromised charging stations could be used to manipulate billing information, causing financial losses for both customers and charging station operators. A large-scale denial-of-service attack could overwhelm the CloudCharge backend, rendering entire charging networks inoperable. Given the worldwide deployment of CloudCharge, the impact could be felt across multiple countries.

## Recommendation

*   Monitor network connections to the CloudCharge infrastructure for suspicious WebSocket traffic originating from unexpected sources, using the `Detect Suspicious CloudCharge WebSocket Connection` Sigma rule.
*   Implement rate limiting on authentication requests to the CloudCharge WebSocket API to mitigate denial-of-service attempts, referencing the information about CVE-2026-25114.
*   Monitor logs for multiple connections using the same charging station identifier, indicating potential session hijacking attempts, using the `Detect CloudCharge Session Hijacking` Sigma rule and the context for CVE-2026-27652.
*   Review and restrict access to web-based mapping platforms that may expose charging station authentication identifiers, mitigating the risk associated with CVE-2026-20733.
*   Contact CloudCharge directly via their support page (https://cloudcharge.tech/support/contact/) to inquire about available patches or mitigations for CVE-2026-20781, CVE-2026-25114, CVE-2026-27652, and CVE-2026-20733.
