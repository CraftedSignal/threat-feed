---
title: Denial of Service Vulnerability in Apache Kafka
slug: 2026-08-apache-kafka-dos
description: A vulnerability in Apache Kafka allows a remote, unauthenticated attacker to trigger a Denial of Service condition by exploiting CVE-2024-27309.
date: "2026-08-12T08:38:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - apache-kafka
vendors:
  - Apache
products:
  - Kafka
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Apache Kafka ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2024-27309
    cvss: 7.4
    epss: 0.01125
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2024-0799
---

A vulnerability has been identified in Apache Kafka that permits a remote, unauthenticated attacker to cause a Denial of Service (DoS) condition. The flaw, tracked as CVE-2024-27309, impacts the availability of the Kafka service. The exploit allows an attacker to send specially crafted requests to the Kafka broker, resulting in resource exhaustion or service interruption. This vulnerability is significant for organizations relying on Apache Kafka for high-throughput, real-time data streaming, as successful exploitation could lead to critical system downtime and service outages within infrastructure environments. Defenders should prioritize patching affected Kafka clusters to the latest available version provided by the Apache Software Foundation to mitigate the risk of disruption.

## Impact

Successful exploitation of this vulnerability results in a Denial of Service, causing the affected Apache Kafka service to become unavailable. This impacts organizations across all sectors that rely on Kafka for data pipeline management, messaging, or real-time stream processing. Sustained service failure can lead to significant operational disruption, data processing delays, and potential loss of data availability if the Kafka cluster acts as a central message broker.

## Recommendation

- Patch Apache Kafka to the version specified by the vendor as containing the fix for CVE-2024-27309.
- Implement network-level access controls to restrict connections to Kafka brokers to only known, authorized clients, reducing the exposure to unauthenticated, remote exploitation attempts.
