---
title: CVE-2026-0258 PAN-OS SSRF vulnerability in IKEv2 certificate URL fetching
slug: 2026-05-panos-ssrf
description: CVE-2026-0258 is a medium severity server-side request forgery (SSRF) vulnerability in Palo Alto Networks PAN-OS that allows an unauthenticated attacker to cause the firewall to send network requests to unintended destinations, potentially leading to a denial of service (DoS).
date: "2026-05-13T16:04:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssrf
  - cve-2026-0258
  - network
  - palo alto networks
vendors:
  - Palo Alto Networks
products:
  - PAN-OS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://security.paloaltonetworks.com/CVE-2026-0258
rules:
  - title: Detect CVE-2026-0258 Exploitation Attempt - Outbound Connection to Non-Standard Port
    description: Detects CVE-2026-0258 exploitation attempt — Outbound connection from PAN-OS firewall to a non-standard port (other than 80, 443, etc.) which may indicate SSRF
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1046
    data_sources:
      - network_connection
      - windows
  - title: Detect CVE-2026-0258 Exploitation Attempt - DNS Query to Internal Hostname
    description: Detects CVE-2026-0258 exploitation attempt — DNS query from PAN-OS firewall to resolve an internal hostname, which may indicate SSRF to internal resource
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1046
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-0258, exists within the IKEv2 implementation of Palo Alto Networks PAN-OS software. This flaw allows an unauthenticated attacker to manipulate the firewall into sending network requests to unintended destinations. Successful exploitation can result in a denial-of-service (DoS) condition. This vulnerability affects PAN-OS versions 12.1 prior to 12.1.4-h5 and 12.1.7, 11.2 prior to 11.2.4-h17, 11.2.7-h13, 11.2.10-h6 and 11.2.12, 11.1 prior to 11.1.4-h33, 11.1.6-h32, 11.1.7-h6, 11.1.10-h25, 11.1.13-h5 and 11.1.15, and 10.2 prior to 10.2.7-h34, 10.2.10-h36, 10.2.13-h21, 10.2.16-h7 and 10.2.18-h6. Panorama, Cloud NGFW, and Prisma Access are not affected. The vulnerability is triggered during IKEv2 certificate URL fetching when a Site-to-Site VPN Gateway with IKEv2 is configured.

## Attack Chain

1.  The attacker identifies a vulnerable PAN-OS firewall with a Site-to-Site VPN Gateway configured for IKEv2.
2.  The attacker crafts a malicious IKEv2 request containing a URL for certificate retrieval.
3.  The crafted URL specifies an internal or unintended external destination.
4.  The PAN-OS firewall, acting as the IKEv2 initiator, parses the malicious IKEv2 request.
5.  The firewall attempts to fetch the certificate from the attacker-controlled URL.
6.  The firewall sends an HTTP(S) request to the specified URL.
7.  If the URL points to an internal resource, the attacker can potentially probe internal services.
8.  If the URL points to an external resource, the attacker can cause the firewall to participate in a DDoS attack or expose sensitive information.

## Impact

Successful exploitation of CVE-2026-0258 can allow an unauthenticated attacker to perform reconnaissance activities against internal network resources, potentially leading to the discovery of sensitive information. The attacker may also trigger a denial-of-service condition by causing the firewall to consume excessive resources or by directing traffic to unintended destinations. While the vulnerability has a medium severity rating, successful exploitation can compromise the confidentiality, integrity, and availability of the affected firewall and the network it protects. Palo Alto Networks is not aware of any malicious exploitation of this issue at this time.

## Recommendation

*   Upgrade PAN-OS to a fixed version as specified in the Palo Alto Networks advisory, prioritizing versions 12.1.7, 11.2.12, 11.1.15, and 10.2.18-h6 (see Product Status table in the advisory).
*   If immediate patching is not feasible, mitigate the risk by removing all IKEv2 VPN gateway configurations, as mentioned in the "Workarounds and Mitigations" section of the advisory.
*   Customers with a Threat Prevention subscription should enable Threat ID 510014 to block potential attacks, as recommended in the "Workarounds and Mitigations" section.
*   Monitor network traffic for unusual outbound connections originating from PAN-OS firewalls, especially connections to internal resources that the firewall should not normally access.
