---
title: 'CVE-2026-0284 PAN-OS: XML Injection Vulnerability in Large Scale VPN (LSVPN)'
slug: 2026-07-pan-os-lsvpn-xml-injection
description: An XML injection vulnerability (CVE-2026-0284) in the Large Scale VPN (LSVPN) functionality of Palo Alto Networks PAN-OS software allows an unauthenticated attacker with network access to inject malicious XML content, potentially leading to information disclosure or corruption of internal LSVPN satellite data.
date: "2026-07-08T16:17:42Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - vulnerability
  - xml-injection
  - pan-os
  - network-device
vendors:
  - Palo Alto Networks
products:
  - PAN-OS 12.1 (< 12.1.4-h8)
  - PAN-OS 12.1 (< 12.1.7-h2)
  - PAN-OS 12.1 (< 12.1.8)
  - PAN-OS 11.2 (< 11.2.4-h20)
  - PAN-OS 11.2 (< 11.2.7-h18)
  - PAN-OS 11.2 (< 11.2.10-h12)
  - PAN-OS 11.2 (< 11.2.13)
  - PAN-OS 11.1 (< 11.1.4-h35)
  - PAN-OS 11.1 (< 11.1.6-h35)
  - PAN-OS 11.1 (< 11.1.7-h8)
  - PAN-OS 11.1 (< 11.1.10-h30)
  - PAN-OS 11.1 (< 11.1.13-h9)
  - PAN-OS 11.1 (< 11.1.16)
  - PAN-OS 10.2 (< 10.2.7-h36)
  - PAN-OS 10.2 (< 10.2.10-h39)
  - PAN-OS 10.2 (< 10.2.13-h23)
  - PAN-OS 10.2 (< 10.2.16-h9)
  - PAN-OS 10.2 (< 10.2.18-h8)
affected_os:
  - PAN-OS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An XML injection vulnerability... enables an unauthenticated attacker with network access to inject malicious XML content
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: potentially leading to information disclosure... of internal LSVPN satellite data.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: corruption of internal LSVPN satellite data.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0284
---

An XML injection vulnerability (CVE-2026-0284) exists in the Large Scale VPN (LSVPN) functionality of Palo Alto Networks PAN-OS software, allowing an unauthenticated attacker with network access to inject malicious XML content. This can lead to information disclosure or corruption of internal LSVPN satellite data. The vulnerability, discovered internally and published on July 8, 2026, impacts firewalls running specific versions of PAN-OS 10.2.x, 11.1.x, 11.2.x, and 12.1.x. Exposure is limited to devices actively using LSVPN with configured satellites. Palo Alto Networks is currently unaware of any malicious exploitation in the wild, but the low attack complexity and lack of user interaction make this a significant concern for vulnerable deployments, necessitating prompt patching to mitigate potential data compromise or service disruption.

## Attack Chain

1. An unauthenticated attacker gains network access to a vulnerable Palo Alto Networks PAN-OS firewall running LSVPN with configured satellites.
2. The attacker identifies the LSVPN functionality exposed through GlobalProtect portals, which is susceptible to XML injection.
3. The attacker crafts a specialized network request containing malicious XML content designed for injection into the LSVPN communication protocol.
4. This crafted XML payload is transmitted to the vulnerable PAN-OS device's LSVPN interface via the network.
5. Due to the XML injection vulnerability (CVE-2026-0284), the PAN-OS firewall incorrectly parses and processes the attacker's malicious XML.
6. The injected XML leads to the unauthorized disclosure of sensitive internal LSVPN satellite configuration data from the firewall.
7. Alternatively, the injected XML could result in the corruption of critical internal LSVPN satellite data, impacting the integrity and availability of VPN operations.

## Impact

If successfully exploited, this vulnerability allows an unauthenticated attacker with network access to achieve information disclosure or corruption of internal LSVPN satellite data. While Palo Alto Networks reports no awareness of in-the-wild exploitation, the potential for unauthorized access to sensitive VPN configuration details or disruption of VPN services due to data corruption could severely impact an organization's network security and availability. The vulnerability has a CVSSv4 score of 7.8 (MEDIUM), with a high subsequent confidentiality impact, indicating that critical data could be exposed.

## Recommendation

* Upgrade affected Palo Alto Networks PAN-OS firewalls to the fixed versions provided for PAN-OS 10.2, 11.1, 11.2, and 12.1.
* Ensure that Threat Prevention subscription customers enable Threat ID 510031 (from Applications and Threats content version 9122-10145 and later) and apply a vulnerability protection security profile to your GlobalProtect interface.
* Check for LSVPN satellite configuration on your PAN-OS firewalls by running `show config running | match satellite` on the CLI to determine exposure to CVE-2026-0284.
