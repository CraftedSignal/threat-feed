---
title: Multiple Vulnerabilities in Chargemap Charging Stations
slug: 2026-02-chargemap-vulns
description: Unauthenticated attackers can exploit multiple vulnerabilities in Chargemap's charging stations, including missing authentication, improper authentication attempt restrictions, insufficient session expiration, and unprotected credentials, potentially leading to unauthorized control and denial-of-service.
date: "2026-02-26T12:00:00Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: domain
    value: chargemap.com
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

Chargemap chargemap.com is affected by multiple critical vulnerabilities that could allow attackers to gain unauthorized administrative control over charging stations or disrupt charging services. These vulnerabilities include missing authentication for critical functions (CVE-2026-25851), improper restriction of excessive authentication attempts (CVE-2026-20792), insufficient session expiration (CVE-2026-25711), and insufficiently protected credentials (CVE-2026-20791). The vulnerabilities affect all versions of Chargemap chargemap.com.  These flaws exist within the WebSocket API and the handling of charging station identifiers. Successful exploitation can lead to privilege escalation, data corruption, session hijacking, and denial-of-service conditions. The affected infrastructure sectors include energy and transportation systems, with deployments worldwide.

## Attack Chain

1.  Attacker identifies a publicly accessible Chargemap charging station identifier via web-based mapping platforms (CVE-2026-20791).
2.  Attacker connects to the OCPP WebSocket endpoint of the targeted charging station using the discovered identifier without authentication (CVE-2026-25851).
3.  Attacker exploits the lack of authentication to impersonate a legitimate charger.
4.  Attacker floods the WebSocket API with authentication requests, leveraging the absence of rate limiting to conduct a denial-of-service attack (CVE-2026-20792).
5.  Attacker hijacks a legitimate charging station session due to insufficient session expiration and predictable session identifiers (CVE-2026-25711).
6.  Attacker sends malicious commands to the backend, disrupting the charging process and potentially damaging connected vehicles.
7.  Attacker manipulates data sent to the backend, corrupting charging network data and potentially causing billing errors or safety issues.
8.  Attacker gains full administrative control over the charging station, enabling them to modify settings, disable functionality, or use it as a pivot point to attack other systems.

## Impact

Successful exploitation of these vulnerabilities could result in widespread disruption of electric vehicle charging services, financial losses due to manipulated charging data, and potential damage to connected vehicles. Given the global deployment of Chargemap, a successful attack could affect numerous users and organizations in the energy and transportation sectors. Attackers could remotely disable charging stations, manipulate pricing, or even cause physical damage to charging infrastructure.  The lack of vendor response further exacerbates the potential impact, leaving users vulnerable without readily available patches or workarounds.

## Recommendation

*   Minimize network exposure for Chargemap charging stations by ensuring they are not directly accessible from the internet as recommended by CISA.
*   Locate control system networks and remote devices behind firewalls, isolating them from business networks as per CISA guidance.
*   Monitor network traffic for excessive authentication attempts targeting Chargemap charging stations to detect potential denial-of-service attacks leveraging CVE-2026-20792. Implement rate limiting where possible.
*   Deploy the Sigma rule "Detect Unauthenticated OCPP WebSocket Connections" to identify unauthorized connections to charging stations exploiting CVE-2026-25851.
*   Contact Chargemap using their contact page (https://chargemap.com/en-us/support) to inquire about available patches or mitigations for these vulnerabilities.
