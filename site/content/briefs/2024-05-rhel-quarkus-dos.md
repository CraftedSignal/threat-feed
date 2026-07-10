---
title: Red Hat Enterprise Linux Quarkus Vulnerabilities Lead to Information Disclosure and Denial of Service
slug: 2024-05-rhel-quarkus-dos
description: Multiple vulnerabilities in Quarkus on Red Hat Enterprise Linux allow a remote attacker to disclose information or trigger a denial of service.
date: "2024-05-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rhel
  - quarkus
  - denial-of-service
  - information-disclosure
  - linux
vendors:
  - Red Hat
products:
  - Red Hat Enterprise Linux
  - Quarkus
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0460
rules:
  - title: Detect Suspicious Quarkus Request Patterns
    description: Detects suspicious request patterns potentially indicative of Quarkus vulnerability exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect High Error Rates on Quarkus Web Server
    description: Detects a sudden increase in server error responses, potentially indicating a denial-of-service attempt against a Quarkus application.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Red Hat Enterprise Linux (RHEL) is susceptible to multiple vulnerabilities in its Quarkus framework. A remote, unauthenticated attacker can exploit these vulnerabilities to achieve information disclosure or trigger a denial-of-service (DoS) condition. While specific CVEs are not detailed in this brief, the potential impact on confidentiality and availability makes this a significant threat. The absence of specific version numbers makes scoping difficult, but all RHEL systems utilizing Quarkus should be considered potentially vulnerable. Successful exploitation could lead to sensitive data exposure and service disruption.

## Attack Chain

1.  The attacker identifies a vulnerable RHEL system running Quarkus exposed to the network.
2.  The attacker sends a specially crafted request to the vulnerable Quarkus application.
3.  Due to a flaw in request parsing or data handling, the Quarkus application processes the malicious request.
4.  The vulnerability leads to either an information disclosure, where sensitive data is leaked in the response.
5.  Alternatively, the vulnerability causes a denial-of-service condition, potentially by exhausting resources.
6.  The Quarkus application becomes unresponsive or crashes, impacting service availability.
7.  The attacker repeats the process to amplify the DoS effect, potentially taking down the entire application or system.

## Impact

Successful exploitation of these vulnerabilities can lead to significant consequences. Information disclosure can expose sensitive data, including credentials, configuration details, or proprietary information. A denial-of-service attack can disrupt critical services, leading to financial losses, reputational damage, and operational downtime. The number of affected systems depends on the prevalence of Quarkus usage within RHEL environments.

## Recommendation

*   Monitor web server logs for unusual request patterns indicative of vulnerability exploitation using the Sigma rule "Detect Suspicious Quarkus Request Patterns".
*   Implement rate limiting and request filtering on systems running Quarkus to mitigate potential DoS attacks.
*   Regularly audit and patch systems running Red Hat Enterprise Linux and Quarkus to remediate any identified vulnerabilities.
