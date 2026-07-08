---
title: 'CVE-2026-0283: Authentication Bypass in Palo Alto Networks PAN-OS Large Scale VPN (LSVPN)'
slug: 2026-07-pan-os-lsvpn-auth-bypass
description: An authentication bypass vulnerability, CVE-2026-0283, in Palo Alto Networks PAN-OS software allows an unauthenticated attacker with network access to establish an unauthorized site-to-site VPN connection when LSVPN functionality with configured satellites is enabled, leading to potential access to internal network resources.
date: "2026-07-08T16:11:35Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - authentication-bypass
  - vpn
  - network-device
  - palo-alto-networks
  - pan-os
vendors:
  - Palo Alto Networks
products:
  - PAN-OS 12.1
  - PAN-OS 11.2
  - PAN-OS 11.1
  - PAN-OS 10.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authentication bypass vulnerability in Large Scale VPN ( LSVPN) functionality of Palo Alto Networks PAN-OS software allows an attacker with network access to bypass security restrictions and establish an unauthorized site-to-site VPN connection.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0283
---

Palo Alto Networks has disclosed CVE-2026-0283, an authentication bypass vulnerability affecting specific versions of PAN-OS software when configured with Large Scale VPN (LSVPN) and active satellites. Discovered internally, this vulnerability allows an attacker with network access to bypass security restrictions and establish an unauthorized site-to-site VPN connection without prior authentication. The flaw impacts PAN-OS 10.2, 11.1, 11.2, and 12.1, but does not affect Panorama, Cloud NGFW, or Prisma Access. Exploitation requires the firewall to have LSVPN satellites explicitly configured. While currently unreported as being actively exploited in the wild, the vulnerability could grant unauthorized access to sensitive internal networks, making it a significant concern for organizations relying on these PAN-OS deployments.

## Attack Chain

1. Attacker identifies a vulnerable Palo Alto Networks PAN-OS firewall with LSVPN enabled and publicly accessible via the network.
2. Attacker initiates a connection attempt to the vulnerable LSVPN endpoint on the firewall.
3. Attacker sends a specially crafted network request designed to exploit the authentication bypass vulnerability, CVE-2026-0283.
4. The vulnerable PAN-OS software incorrectly processes the request, failing to enforce proper authentication due to the flaw.
5. Attacker successfully establishes an unauthorized site-to-site VPN tunnel, gaining network-level access through the compromised firewall.
6. The attacker can then perform internal network reconnaissance, attempt lateral movement, or potentially exfiltrate sensitive data from the connected network segment.

## Impact

Successful exploitation of CVE-2026-0283 leads to an unauthorized site-to-site VPN connection, granting attackers direct access to the internal network resources protected by the vulnerable firewall. This unauthorized access can result in severe confidentiality breaches, as attackers may gain the ability to view, modify, or exfiltrate sensitive data. While the vulnerability itself does not directly impact the integrity or availability of the firewall, the subsequent access to the internal network can lead to further compromises, service disruption, and potential data loss, depending on the attacker's objectives and the network's configuration.

## Recommendation

* Immediately upgrade affected Palo Alto Networks PAN-OS firewalls to the fixed versions for CVE-2026-0283, specifically: PAN-OS 12.1.4-h8 or later, 12.1.7-h2 or later, 12.1.8 or later; PAN-OS 11.2.4-h20 or later, 11.2.7-h18 or later, 11.2.10-h12 or later, 11.2.13 or later; PAN-OS 11.1.4-h35 or later, 11.1.6-h35 or later, 11.1.7-h8 or later, 11.1.10-h30 or later, 11.1.13-h9 or later, 11.1.16 or later; PAN-OS 10.2.7-h36 or later, 10.2.10-h39 or later, 10.2.13-h23 or later, 10.2.16-h9 or later, 10.2.18-h8 or later.
* Verify if your firewall has LSVPN satellites configured by running `show config running | match satellite` from the PAN-OS CLI or checking `Network > GlobalProtect > Portals` in the web interface as mentioned in the CVE-2026-0283 advisory.
* Deploy Threat Prevention content version 9122-10145 or later and enable Threat ID 510032, applying the vulnerability protection security profile to your GlobalProtect interface for limited coverage against CVE-2026-0283.
