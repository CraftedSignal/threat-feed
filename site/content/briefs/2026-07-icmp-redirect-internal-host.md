---
title: Suspicious ICMP Redirect Messages from Internal Hosts Indicating MITM Activity
slug: 2026-07-icmp-redirect-internal-host
description: This brief details the detection of ICMP Redirect messages (IPv4 type 5, IPv6 type 137) originating from internal IP addresses, which strongly indicates Adversary-in-the-Middle (MITM) activity designed to manipulate routing, potentially leading to credential access or data exfiltration by directing target host traffic through a compromised internal system.
date: "2026-07-05T02:03:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - network-security
  - credential-access
  - mitm
  - icmp
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: A workstation or server emitting redirects can indicate route manipulation for adversary-in-the-middle activity.
    confidence_band: high
references:
  - https://www.rfc-editor.org/rfc/rfc792
  - https://www.rfc-editor.org/rfc/rfc4443
  - https://zimperium.com/blog/doubledirect-zimperium-discovers-full-duplex-icmp-redirect-attacks-in-the-wild
rules:
  - title: ICMP Redirect Message from Internal Host
    description: Identifies ICMP Redirect messages (type 5 for IPv4, type 137 for IPv6) sourced from an internal IPv4 or IPv6 address, indicating potential Adversary-in-the-Middle activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1557
    data_sources:
      - network_connection
rules_count: 1
---

This threat focuses on the detection of malicious Internet Control Message Protocol (ICMP) Redirect messages (specifically IPv4 type 5 and IPv6 type 137) when sourced from an internal host that is not an authorized network router or gateway. While legitimate ICMP Redirects are typically sent by on-path routers to optimize network paths, a workstation or server emitting such messages is a strong indicator of Adversary-in-the-Middle (MITM) activity. This technique allows attackers to manipulate routing tables on other internal hosts, compelling them to send traffic through a compromised system. The objective is often to intercept sensitive communications, capture credentials, or exfiltrate data. This type of network manipulation is critical for defenders to identify, as it enables further stages of attack by subverting network trust and control.

## Attack Chain

1.  An adversary gains initial access to an internal host within the victim's network (e.g., via a successful phishing campaign or exploitation of a vulnerable service).
2.  The adversary establishes persistence on the compromised host and prepares it for network manipulation, installing necessary tools or modifying system configurations.
3.  The compromised host is configured to emit malicious ICMP Redirect messages, specifically Type 5 for IPv4 or Type 137 for IPv6.
4.  The compromised host sends these ICMP Redirect messages to other target hosts on the same network segment, instructing them to update their routing tables for specific destinations (e.g., DNS servers, authentication servers, internet gateways).
5.  Target hosts receive and process the malicious ICMP Redirects, modifying their local routing tables to direct traffic for the specified destinations through the compromised adversary-controlled host.
6.  Traffic intended for legitimate network resources (e.g., Active Directory controllers, web servers, external services) is now rerouted to pass through the adversary's compromised host.
7.  The adversary performs traffic interception, inspection, and potentially modification on the redirected network traffic.
8.  The adversary captures sensitive information such as credentials, session tokens, or proprietary data, achieving credential access, data exfiltration, or further attack objectives.

## Impact

A successful Adversary-in-the-Middle attack leveraging ICMP Redirects can have severe consequences, allowing attackers to intercept virtually any network traffic between the affected clients and their intended destinations. This can lead to the theft of sensitive data, including login credentials, intellectual property, and financial information. Attackers can also inject malicious content into intercepted communications, leading to further compromises or the deployment of malware. While no specific victim counts or sectors are named, organizations relying heavily on network segmentation and secure internal communications are particularly at risk, as this technique undermines foundational network trust.

## Recommendation

*   Deploy the Sigma rule "ICMP Redirect Message from Internal Host" to your SIEM and tune for your environment, paying close attention to `IcmpType` and `SourceIp` fields.
*   Investigate alerts from the "ICMP Redirect Message from Internal Host" rule by identifying the `source.ip` and verifying if it is an authorized router or gateway.
*   Review the `IcmpType` (5 or 137) and adjacent flow records for the redirect target and affected destination to understand which routes or resolvers were being manipulated.
*   Disable ICMP redirect acceptance on client workstations and servers where policy allows to mitigate the effectiveness of T1557.
*   Ensure `network_traffic.icmp` data streams are being collected from your network environment to enable detection of this activity.
