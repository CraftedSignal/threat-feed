---
title: RabbitMQ Stream Listener Vulnerability CVE-2026-57220 Allows Unauthenticated Memory Exhaustion DoS
slug: 2026-07-rabbitmq-memexhaust-dos
description: A denial-of-service vulnerability, CVE-2026-57220, exists in the RabbitMQ stream listener that allows an unauthenticated attacker to exhaust memory resources by not properly enforcing frame-size limits during authentication, leading to service disruption.
date: "2026-07-15T07:45:46Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:broadcom:rabbitmq_server:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - rabbitmq
vendors:
  - RabbitMQ
products:
  - RabbitMQ Stream listener
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A denial-of-service vulnerability (CVE-2026-57220) exists in the RabbitMQ stream listener. This flaw allows an unauthenticated attacker to exhaust memory resources by not properly enforcing frame-size limits during the authentication process, leading to a denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-57220
    cvss: 7.5
    epss: 0.00515
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57220
---

A critical denial-of-service (DoS) vulnerability, tracked as CVE-2026-57220, has been disclosed in the RabbitMQ Stream listener component. This flaw stems from an insufficient enforcement of configured frame-size limits during the authentication process. An unauthenticated remote attacker can exploit this vulnerability by sending specially crafted stream data frames that exceed expected size restrictions. The RabbitMQ Stream listener, failing to properly validate these frames, will attempt to process them, leading to excessive memory allocation and eventual memory exhaustion of the server process. This can cause the RabbitMQ service to crash or become unresponsive, resulting in a denial of service for legitimate users. This vulnerability impacts installations utilizing the RabbitMQ Stream listener, posing a significant risk to the availability of message queuing services.

## Attack Chain

1. An unauthenticated attacker establishes a TCP connection to the vulnerable RabbitMQ Stream listener port.
2. The attacker initiates the authentication handshake with the RabbitMQ Stream listener.
3. During the authentication phase, the attacker sends a continuous stream of data.
4. The attacker crafts the stream to contain oversized data frames that intentionally violate the configured frame-size limits.
5. Due to CVE-2026-57220, the RabbitMQ Stream listener fails to correctly apply the frame-size limits during this specific pre-authentication stage.
6. The listener attempts to buffer and process these excessively large frames in memory.
7. This continuous influx of oversized frames causes the RabbitMQ process to rapidly consume available system memory.
8. Memory exhaustion occurs, leading to the RabbitMQ service crashing or becoming unresponsive, effectively achieving a denial of service.

## Impact

Successful exploitation of CVE-2026-57220 leads to an immediate and complete denial of service for the affected RabbitMQ instance. As the attack is unauthenticated, any internet-facing or internally accessible RabbitMQ Stream listener is vulnerable to disruption. Organizations relying on RabbitMQ for critical message queuing, task distribution, or real-time communication will experience severe operational outages, data processing delays, and potential data loss if the service crashes. The ease of exploitation and potential for significant business impact categorize this as a high-severity threat requiring urgent remediation.

## Recommendation

* Patch CVE-2026-57220 immediately on all affected RabbitMQ Stream listener deployments to mitigate the unauthenticated memory exhaustion vulnerability.
