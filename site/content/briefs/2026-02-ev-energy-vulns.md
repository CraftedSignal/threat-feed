---
title: Multiple Vulnerabilities in EV Energy ev.energy Charging Stations
slug: 2026-02-ev-energy-vulns
description: Multiple vulnerabilities exist in EV Energy ev.energy that could allow an attacker to gain unauthorized administrative control over vulnerable charging stations or disrupt charging services through denial-of-service attacks.
date: "2026-02-26T12:00:00Z"
type: advisory
types:
  - advisory
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

Multiple vulnerabilities have been identified in EV Energy ev.energy charging stations, potentially allowing attackers to gain unauthorized administrative control or disrupt charging services. The vulnerabilities, detailed in CISA ICS Advisory ICSA-26-057-07, affect all versions of ev.energy. These vulnerabilities include missing authentication for critical functions (CVE-2026-27772), improper restriction of excessive authentication attempts (CVE-2026-24445), insufficient session expiration (CVE-2026-26290), and insufficiently protected credentials (CVE-2026-25774). Successful exploitation could lead to privilege escalation, unauthorized control of charging infrastructure, and denial-of-service conditions. The affected sectors include Energy and Transportation Systems, with worldwide deployment. The vendor, EV Energy, has not responded to CISA's request for coordination.

## Attack Chain

1.  **Reconnaissance:** An attacker identifies EV Energy ev.energy charging stations that have publicly accessible authentication identifiers via web-based mapping platforms (CVE-2026-25774).
2.  **Unauthorized WebSocket Connection:** The attacker connects to the OCPP WebSocket endpoint using a known charging station identifier without proper authentication (CVE-2026-27772).
3.  **Session Hijacking:** The attacker exploits the lack of session expiration and predictable session identifiers to hijack a legitimate charging station's session (CVE-2026-26290).
4.  **Data Manipulation:** The attacker issues unauthorized OCPP commands, manipulating data sent to the backend and gaining unauthorized control of the charging infrastructure (CVE-2026-27772).
5.  **Privilege Escalation:** Through unauthorized access and command execution, the attacker escalates privileges to administrative control over the charging station (CVE-2026-27772).
6.  **Denial-of-Service:** Alternatively, the attacker floods the WebSocket API with excessive authentication requests, causing a denial-of-service condition by suppressing or misrouting legitimate charger telemetry (CVE-2026-24445).
7.  **Service Disruption:** Legitimate users are unable to use the charging stations due to the attacker's control or the denial-of-service condition.
8.  **Network Data Corruption:** The attacker manipulates charging network data reported to the backend, potentially impacting billing or grid management systems (CVE-2026-27772).

## Impact

Successful exploitation of these vulnerabilities can lead to significant disruptions in the Energy and Transportation Systems sectors. An attacker could gain administrative control over charging stations, manipulate charging processes, and cause denial-of-service conditions, rendering the stations unusable. The lack of vendor response further exacerbates the risk, leaving users without official patches or mitigation guidance. The compromise of charging network data could also have downstream impacts on billing and grid management systems.

## Recommendation

*   Implement rate limiting on WebSocket authentication requests to mitigate CVE-2026-24445, preventing denial-of-service attacks. Monitor network traffic for excessive authentication attempts targeting OCPP WebSocket endpoints, and deploy a custom rule to detect such attempts.
*   Disable or restrict public access to web-based mapping platforms that expose charging station authentication identifiers to mitigate CVE-2026-25774. Conduct regular audits of publicly available information to identify and remove exposed credentials.
*   Deploy network segmentation and firewall rules to minimize network exposure for all charging station devices, as recommended by CISA. This will limit the attack surface and prevent unauthorized access from the Internet.
