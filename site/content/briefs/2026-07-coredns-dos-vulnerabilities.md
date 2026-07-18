---
title: 'CoreDNS: Multiple Vulnerabilities Enable Denial of Service'
slug: 2026-07-coredns-dos-vulnerabilities
description: Multiple vulnerabilities exist in CoreDNS that allow a remote, unauthenticated attacker to execute a Denial of Service (DoS) attack against the service, potentially leading to service disruption and unavailability for affected systems utilizing CoreDNS.
date: "2026-07-17T06:09:21Z"
lastmod: "2026-07-18T07:04:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - coredns
  - dns
  - denial-of-service
  - vulnerability
  - network
vendors:
  - CoreDNS
products:
  - CoreDNS
  - proxyproto plugin
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in CoreDNS ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
cves:
  - id: CVE-2026-62309
    cvss: 7.5
    epss: 0.0035
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2271
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62309
updates:
  - at: "2026-07-18T07:04:43Z"
    level: L2
    summary: added CVE-2026-62309
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-62309
---

Recently disclosed by CERT-Bund, multiple vulnerabilities have been identified in CoreDNS, a widely used DNS server. These vulnerabilities can be exploited by a remote, unauthenticated attacker to initiate a Denial of Service (DoS) attack against affected CoreDNS instances. This threat is critical because CoreDNS is often deployed in foundational network infrastructure, including Kubernetes clusters, where its disruption can severely impact critical services and applications. The specifics of these vulnerabilities and their exploitation methods are not detailed in the public advisory, but their existence poses a significant risk to the availability and stability of DNS resolution within an organization's network. Organizations utilizing CoreDNS should prioritize patching to mitigate potential service outages.

## Attack Chain

1. A remote, unauthenticated attacker identifies a vulnerable CoreDNS instance exposed on the network.
2. The attacker crafts and sends specially malformed requests or sequences of requests, leveraging one or more of the identified vulnerabilities in CoreDNS.
3. These requests exploit weaknesses within the CoreDNS application, such as improper handling of specific DNS queries or resource consumption issues.
4. The vulnerable CoreDNS instance begins to consume excessive resources (CPU, memory, network bandwidth) or encounters an unhandled exception.
5. The CoreDNS service becomes unresponsive or crashes, leading to a disruption in DNS resolution.
6. Dependent services and applications that rely on the compromised CoreDNS instance experience outages or degraded performance due to a lack of DNS resolution.
7. The final objective is a complete Denial of Service for DNS services and any systems relying on them.

## Impact

Successful exploitation of these CoreDNS vulnerabilities can result in a significant Denial of Service affecting an organization's critical network infrastructure. This can lead to widespread service unavailability for any application or system that relies on the compromised CoreDNS instance for name resolution. For environments like Kubernetes, where CoreDNS is often integral to service discovery, a DoS event can bring down entire clusters, causing substantial operational disruption, data access issues, and potential financial losses due to downtime. The number of potential victims is high given CoreDNS's broad adoption, particularly in cloud-native and containerized environments.

## Recommendation

* Update all CoreDNS installations to the latest patched version to remediate the identified vulnerabilities.
* Implement network ingress filtering to restrict access to CoreDNS servers only from trusted internal sources, limiting exposure to remote, unauthenticated attackers.
* Monitor CoreDNS system logs (`CoreDNS` logs) for unusual errors, repeated restarts, or excessive resource consumption.
* Deploy network-level monitoring (`network_connection` logs) to detect abnormal traffic patterns targeting CoreDNS, such as a high volume of malformed or unexpected DNS queries from external sources.
