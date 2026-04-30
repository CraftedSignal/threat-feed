---
title: EV2GO Charging Station Vulnerabilities Allow Impersonation and Denial of Service
slug: 2026-02-ev2go-vulns
description: Multiple vulnerabilities in EV2GO charging stations, including missing authentication and session management flaws, could allow attackers to impersonate stations, hijack sessions, and cause denial-of-service conditions.
date: "2026-02-27T10:00:00Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: domain
    value: ev2go.io
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

Multiple vulnerabilities have been discovered in EV2GO ev2go.io charging stations. These vulnerabilities, identified as CVE-2026-24731, CVE-2026-25945, CVE-2026-20895, and CVE-2026-22890, relate to missing authentication for critical functions, improper restriction of excessive authentication attempts, insufficient session expiration, and insufficiently protected credentials. Successful exploitation of these flaws could enable attackers to impersonate charging stations, hijack legitimate user sessions, suppress or misroute traffic, potentially leading to a large-scale denial-of-service (DoS) attack. These vulnerabilities affect all versions of ev2go.io and impact critical infrastructure sectors such as energy and transportation systems globally. The lack of vendor response to reported vulnerabilities further exacerbates the risk.

## Attack Chain

1.  Attacker identifies a valid charging station identifier using publicly accessible mapping platforms, exploiting CVE-2026-22890.
2.  Attacker connects to the OCPP WebSocket endpoint of a charging station without proper authentication, leveraging CVE-2026-24731.
3.  Attacker issues unauthorized OCPP commands to the backend as a legitimate charger, due to the missing authentication mechanisms (CVE-2026-24731).
4.  Attacker attempts multiple authentication requests without any rate limiting, potentially leading to a denial-of-service (DoS) by overwhelming the backend (CVE-2026-25945).
5.  Attacker hijacks or shadows existing sessions due to predictable session identifiers and the ability for multiple endpoints to connect using the same identifier (CVE-2026-20895).
6.  Legitimate charging station is displaced, and the attacker receives backend commands intended for the original station (CVE-2026-20895).
7.  Attacker manipulates charging station operations or charging network data reported to the backend.
8.  Final objective: Cause disruption of charging services for users, corrupt charging network data, or potentially gain control of the charging infrastructure.

## Impact

Successful exploitation of these vulnerabilities could have significant consequences. An attacker can disrupt charging services, leading to stranded electric vehicles and customer dissatisfaction. Data manipulation could result in incorrect billing or inaccurate reporting. A large-scale denial-of-service attack could impact entire charging networks, affecting energy distribution and transportation systems. Given the widespread deployment of EV2GO charging stations worldwide, a successful attack could affect a large number of users and critical infrastructure.

## Recommendation

*   Monitor network traffic for connections to `ev2go.io` that do not originate from known, authorized charging stations.
*   Implement rate limiting on authentication attempts to the OCPP WebSocket API to mitigate CVE-2026-25945.
*   Deploy the Sigma rule "Detect Unauthorized OCPP Connection" to identify potential station impersonation attempts based on CVE-2026-24731.
*   Monitor for unexpected OCPP commands being issued from charging stations that are not aligned with normal operation to detect malicious manipulation of charging infrastructure, as described in CVE-2026-24731.
*   Contact EV2GO at https://ev2go.io/ for information on patching or mitigating these vulnerabilities.
