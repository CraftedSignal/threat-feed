---
title: Multiple HAProxy Vulnerabilities Lead to Denial of Service
slug: 2026-07-haproxy-dos
description: Multiple vulnerabilities exist in HAProxy Enterprise, Community, and ALOHA, specifically impacting QUIC implementations, which a remote, unauthenticated attacker can exploit to execute a Denial of Service (DoS) attack, disrupting service availability.
date: "2026-07-21T07:45:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - network-device
vendors:
  - HAProxy Technologies
products:
  - HAProxy Enterprise (QUIC)
  - HAProxy Community (QUIC)
  - HAProxy ALOHA (QUIC)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in HAProxy Enterprise, Community und ALOHA ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0410
---

The German Federal Office for Information Security (BSI) issued an advisory on July 21, 2026, detailing multiple vulnerabilities within HAProxy Enterprise, Community, and ALOHA products, specifically affecting their QUIC implementations. These flaws can be exploited by a remote, unauthenticated attacker to execute a Denial of Service (DoS) attack. The lack of authentication required for exploitation means these vulnerabilities pose a significant risk to the availability and stability of services relying on HAProxy as a load balancer or proxy, allowing attackers to disrupt critical network infrastructure. The advisory does not specify the exact nature of the vulnerabilities or provide CVEs, but emphasizes the potential for complete service disruption across affected versions.

## Impact

A successful exploitation of these vulnerabilities leads to a Denial of Service against HAProxy instances, affecting critical services that rely on them for load balancing, traffic routing, or proxying. While specific victim numbers or targeted sectors are not detailed, any organization utilizing affected versions of HAProxy Enterprise, Community, or ALOHA with QUIC enabled is at risk. The primary impact is a loss of availability for networked applications and services, which can lead to significant operational disruptions, financial losses, and reputational damage.

## Recommendation

* Consult the vendor advisory for specific patch versions or mitigation strategies to address the identified Denial of Service vulnerabilities in HAProxy Enterprise, Community, and ALOHA products utilizing QUIC.
* Review network logs, specifically `category: network_connection` logs, for unusual traffic patterns or connection drops that could indicate a Denial of Service attack against HAProxy instances.
