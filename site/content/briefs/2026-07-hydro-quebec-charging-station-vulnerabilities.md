---
title: Critical Vulnerabilities in Hydro-Québec Le Circuit Electrique Charging Station Backend
slug: 2026-07-hydro-quebec-charging-station-vulnerabilities
description: Multiple critical vulnerabilities, including improper access control (CVE-2026-20744), improper restriction of excessive authentication attempts (CVE-2026-42952), and insufficient session expiration (CVE-2026-44383), affect Hydro-Québec Le Circuit Electrique charging station backend versions prior to June 2026, which if exploited could lead to privilege escalation or denial-of-service impacting critical transportation infrastructure.
date: "2026-07-07T16:47:40Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - ics
  - vulnerability
  - denial-of-service
  - privilege-escalation
  - transportation
vendors:
  - Hydro-Québec
products:
  - Hydro-Québec Le Circuit Electrique charging station backend (<June_2026)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The charging station websocket endpoint accepts connections without proper authentication, which could lead to privilege escalation.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The charging station websocket endpoint accepts connections without proper authentication, which could lead to privilege escalation.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Deny Access to Resources
    evidence: Previously, there was no throttling on repeated authentication attempts to the charging station backend, which could allow an attacker to execute a Denial-of-Service attack.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Deny Access to Resources
    evidence: Multiple connections to the backend using the same charging station ID are allowed, which could allow an attacker to deploy multiple instances of malicious OCPP clients to overwhelm the backend.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-188-01
  - https://www.cve.org/CVERecord?id=CVE-2026-20744
  - https://www.cve.org/CVERecord?id=CVE-2026-42952
  - https://www.cve.org/CVERecord?id=CVE-2026-44383
---

CISA has issued an advisory detailing three critical and high-severity vulnerabilities affecting the Hydro-Québec Le Circuit Electrique charging station backend, specifically in versions released prior to June 2026. These vulnerabilities, identified as CVE-2026-20744 (CVSS 9.8 Critical), CVE-2026-42952 (CVSS 7.5 High), and CVE-2026-44383 (CVSS 7.5 High), could allow remote attackers to achieve privilege escalation or execute denial-of-service attacks. The vulnerabilities stem from improper access control on the websocket endpoint, a lack of throttling for authentication attempts, and allowing multiple connections with the same charging station ID. The affected systems are deployed in Canada within the transportation systems critical infrastructure sector. While no active exploitation has been reported to CISA, the potential impact underscores the importance for operators to apply available mitigations immediately.

## Attack Chain

1.  **Reconnaissance**: An attacker identifies a publicly exposed Hydro-Québec Le Circuit Electrique charging station backend instance.
2.  **Initial Access (CVE-2026-20744)**: The attacker connects to the charging station's websocket endpoint without authentication, leveraging the Improper Access Control vulnerability (CVE-2026-20744).
3.  **Privilege Escalation**: Due to the absence of proper authentication, the attacker gains unauthorized access and potentially escalates privileges within the backend system.
4.  **Impact - DoS via Excessive Authentication (CVE-2026-42952)**: Alternatively, the attacker sends a high volume of repeated authentication attempts to the charging station backend, exploiting CVE-2026-42952, which lacks throttling mechanisms.
5.  **Impact - DoS via Multiple Connections (CVE-2026-44383)**: Alternatively, the attacker establishes numerous simultaneous connections to the backend using the same charging station ID, exploiting CVE-2026-44383 (Insufficient Session Expiration).
6.  **Service Disruption**: Both Denial-of-Service vulnerabilities (CVE-2026-42952 and CVE-2026-44383) overwhelm the backend, causing it to become unresponsive or unavailable, disrupting the charging station services.
7.  **Adverse Impact**: The ultimate objective is either unauthorized control and privilege escalation on the backend system or a denial of service, rendering the charging station backend inoperable for legitimate users and impacting critical transportation services.

## Impact

Successful exploitation of these vulnerabilities could result in severe consequences for the Hydro-Québec Le Circuit Electrique charging station backend, which is part of Canada's critical transportation infrastructure. An attacker could achieve full privilege escalation, gaining unauthorized control over the backend system, potentially manipulating charging operations or accessing sensitive data. Alternatively, denial-of-service attacks could render the charging stations inoperable, preventing users from accessing charging services and causing widespread disruption to electric vehicle infrastructure. While CISA has not reported any known public exploitation, the high CVSS scores and the nature of the vulnerabilities suggest a high potential for significant operational disruption if targeted.

## Recommendation

*   **Apply Patches/Mitigations**: Immediately apply Hydro-Québec's recommended updates which disable OCPP or implement authentication systems for affected charging stations.
*   **Network Segmentation**: Minimize network exposure for all control system devices and systems, ensuring they are not accessible from the internet, as advised by CISA.
*   **Firewall & Isolation**: Locate control system networks and remote devices behind firewalls and isolate them from business networks to limit exposure to CVE-2026-20744, CVE-2026-42952, and CVE-2026-44383.
*   **Secure Remote Access**: When remote access is required, use secure methods such as Virtual Private Networks (VPNs) and ensure they are updated to the most current version available.
*   **Monitor for Anomalies**: Continuously monitor network traffic to and from the charging station backend for unusual connection attempts, high volumes of authentication requests, or excessive connections from single IDs that could indicate exploitation of CVE-2026-42952 or CVE-2026-44383.
