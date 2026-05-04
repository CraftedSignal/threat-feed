---
title: Multiple Vulnerabilities in Rapid7 Velociraptor
slug: 2026-05-velociraptor-vulns
description: Multiple vulnerabilities in Rapid7 Velociraptor could allow an attacker to disclose information or cause a denial of service.
date: "2026-05-04T09:14:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - information-disclosure
vendors:
  - Rapid7
products:
  - Velociraptor
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: Endpoint Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1305
rules:
  - title: Detect Suspicious HTTP Requests to Velociraptor
    description: Detects HTTP requests to Velociraptor that may indicate exploitation attempts based on abnormal request characteristics.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of Requests to Velociraptor from Single Source IP
    description: Detects potential denial-of-service attempts by monitoring the number of requests to Velociraptor from a single IP address within a short timeframe.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Multiple vulnerabilities have been identified in Rapid7 Velociraptor. An attacker could potentially exploit these vulnerabilities to achieve information disclosure or to trigger a denial-of-service (DoS) condition. While specific CVEs or technical details are not provided in the advisory, the potential impact necessitates proactive monitoring and mitigation strategies to prevent exploitation. This issue was reported on 2026-05-04. Defenders should monitor for unusual activity related to Velociraptor instances, particularly activity indicative of unauthorized data access or resource exhaustion.

## Attack Chain

1. The attacker identifies a vulnerable instance of Rapid7 Velociraptor.
2. The attacker crafts a malicious request targeting one of the undisclosed vulnerabilities.
3. The vulnerable Velociraptor instance processes the malicious request.
4. For information disclosure, the system exposes sensitive data such as configuration details, user information, or internal system data, accessible to the attacker.
5. For Denial of Service, the vulnerable component consumes excessive resources (CPU, memory, network bandwidth).
6. Legitimate user requests to Velociraptor are delayed or fail due to resource exhaustion.
7. The attacker repeats the malicious request to sustain the Denial of Service condition.

## Impact

Successful exploitation of these vulnerabilities could lead to unauthorized disclosure of sensitive information managed by Rapid7 Velociraptor. A denial-of-service attack could disrupt monitoring operations and prevent legitimate users from accessing or utilizing the Velociraptor platform, impacting incident response capabilities. The number of affected instances and specific sectors are currently unknown.

## Recommendation

*   Monitor network traffic to Velociraptor instances for suspicious patterns and anomalies indicative of exploitation attempts (network_connection).
*   Implement rate limiting and input validation mechanisms on Velociraptor endpoints to mitigate potential DoS attacks and information disclosure vulnerabilities (webserver).
*   Monitor Velociraptor logs for error messages or unusual activity patterns that may indicate exploitation attempts (file_event).
