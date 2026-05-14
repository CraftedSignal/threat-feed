---
title: Siemens Opcenter RDnL Missing Authentication Vulnerability (CVE-2026-27446)
slug: 2026-05-siemens-opcenter-rce
description: Siemens Opcenter RDnL is vulnerable to missing authentication in critical function (CVE-2026-27446), where an unauthenticated attacker can use the Core protocol to force a target broker to establish an outbound Core federation connection to an attacker-controlled rogue broker, potentially leading to availability impacts and message injection.
date: "2026-05-14T15:03:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apache:activemq_artemis:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:artemis:2.50.0:*:*:*:*:*:*:*
tags:
  - cve
  - vulnerability
  - siemens
  - activemq
vendors:
  - Siemens
  - Apache
products:
  - Opcenter RDnL
  - ActiveMQ Artemis
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-27446
    cvss: 9.8
    epss: 0.00156
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-134-09
  - https://www.cve.org/CVERecord?id=CVE-2026-27446
  - https://artemis.apache.org/components/artemis/documentation/latest/intercepting-operations.html
rules:
  - title: Detect Outbound Core Protocol Connection
    description: Detects outbound connections using the ActiveMQ Artemis Core protocol, which could indicate exploitation of CVE-2026-27446.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect ActiveMQ Artemis Core Interceptor Bypass
    description: Detects potential bypass of ActiveMQ Artemis Core Interceptor mitigation by monitoring for specific Core protocol packets.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Siemens Opcenter RDnL is affected by a missing authentication vulnerability (CVE-2026-27446) within the ActiveMQ Artemis component. This vulnerability allows an unauthenticated attacker within the adjacent network to exploit the Core protocol. By doing so, the attacker can force a targeted broker to establish an outbound Core federation connection to a malicious, attacker-controlled broker. This could result in availability impacts due to disruption of service and potentially message injection into queues via the rogue broker, leading to data integrity issues within the Opcenter RDnL environment. The advisory recommends updating to Apache Artemis version 2.52.0 or later to mitigate this risk.

## Attack Chain

1.  Attacker identifies a vulnerable Siemens Opcenter RDnL instance with exposed ActiveMQ Artemis.
2.  Attacker establishes a network connection to the targeted ActiveMQ Artemis broker using the Core protocol.
3.  Attacker sends a crafted Core protocol message to the target broker.
4.  The crafted message forces the target broker to initiate an outbound Core federation connection to the attacker's rogue broker.
5.  The target broker establishes a connection to the attacker-controlled rogue broker.
6.  The attacker injects malicious messages into queues managed by the rogue broker.
7.  The rogue broker forwards the injected messages into the target Opcenter RDnL system via the established federation.
8.  The injected messages compromise data integrity and potentially disrupt operations, leading to availability impacts.

## Impact

Successful exploitation of CVE-2026-27446 can lead to message injection and exfiltration, potentially impacting the availability and integrity of Siemens Opcenter RDnL. Given the deployment of Opcenter RDnL in critical manufacturing sectors worldwide, a successful attack could disrupt production processes, compromise product quality, and result in significant financial losses. The vulnerability is rated with a CVSS v3 score of 7.1, indicating a high severity.

## Recommendation

*   Apply the vendor-provided fix by upgrading to Apache Artemis version 2.52.0 or later, as recommended in the advisory to remediate CVE-2026-27446.
*   Implement a Core interceptor to deny all Core downstream federation connect packets, specifically packets with a type of (int) -16 or (byte) 0xfffffff0, as suggested in the advisory.
*   Deploy the Sigma rule "Detect Outbound Core Protocol Connection" to identify potential exploitation attempts of CVE-2026-27446 by monitoring for outbound connections using the Core protocol.
