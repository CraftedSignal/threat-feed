---
title: 'CVE-2026-0285 PAN-OS: Server-Side Request Forgery Vulnerability in Management Web Interface'
slug: 2026-07-panos-ssrf
description: A server-side request forgery (SSRF) vulnerability, tracked as CVE-2026-0285, exists in the management web interface of Palo Alto Networks PAN-OS software, allowing an authenticated administrator with network access to make unauthorized requests from the firewall to internal services, potentially leading to information disclosure or further network compromise.
date: "2026-07-08T16:14:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - server-side-request-forgery
  - ssrf
  - vulnerability
  - pan-os
  - palo-alto-networks
  - network-device
vendors:
  - Palo Alto Networks
products:
  - PAN-OS < 12.1.4-h8
  - PAN-OS < 12.1.7-h2
  - PAN-OS < 12.1.8
  - PAN-OS < 11.2.4-h20
  - PAN-OS < 11.2.7-h18
  - PAN-OS < 11.2.10-h11
  - PAN-OS < 11.2.13
  - PAN-OS < 11.1.4-h35
  - PAN-OS < 11.1.6-h35
  - PAN-OS < 11.1.7-h8
  - PAN-OS < 11.1.10-h30
  - PAN-OS < 11.1.13-h9
  - PAN-OS < 11.1.16
  - PAN-OS < 10.2.7-h36
  - PAN-OS < 10.2.10-h39
  - PAN-OS < 10.2.13-h23
  - PAN-OS < 10.2.16-h9
  - PAN-OS < 10.2.18-h8
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: a server-side request forgery (SSRF) vulnerability in Palo Alto Networks PAN-OS software enables an authenticated administrator with network access to the management web interface
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1090
    technique_name: ""
    evidence: make unauthorized requests from the firewall to internal services
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: ""
    evidence: make unauthorized requests from the firewall to internal services
    confidence_band: med
references:
  - https://security.paloaltonetworks.com/CVE-2026-0285
---

Palo Alto Networks has disclosed CVE-2026-0285, a Server-Side Request Forgery (SSRF) vulnerability affecting their PAN-OS software's management web interface. This issue, internally discovered, enables an authenticated administrator with network access to the management interface to force the firewall to make unauthorized requests to internal services. While currently unreported as being maliciously exploited, the vulnerability carries a medium severity rating. Its risk is elevated if the management interface is directly exposed to the internet or untrusted networks, contrary to best practices. Versions of PAN-OS 10.2, 11.1, 11.2, and 12.1 are affected by this flaw, which could facilitate network reconnaissance or bypass internal network segmentation. Panorama, Cloud NGFW, and Prisma® Access products are not impacted.

## Attack Chain

1. **Initial Access**: An attacker gains authenticated access to the Palo Alto Networks PAN-OS management web interface, likely through stolen credentials (T1078) or a prior compromise.
2. **Vulnerability Exploitation**: The authenticated administrator crafts a malicious request leveraging the SSRF vulnerability (CVE-2026-0285, CWE-918) within the PAN-OS management web interface.
3. **Firewall-Initiated Request**: The vulnerable PAN-OS firewall is tricked into initiating an arbitrary HTTP/S request from its own network context to a target specified by the attacker.
4. **Internal Network Access**: The firewall, acting as an unwitting proxy, makes the unauthorized request to an internal service or host that is typically not directly reachable by the attacker's client.
5. **Information Disclosure/Service Interaction**: The firewall processes the response from the internal service and potentially relays sensitive information or the results of service interaction back to the authenticated administrator via the management interface.
6. **Lateral Movement/Reconnaissance**: The attacker uses the disclosed information or the ability to interact with internal services to conduct further reconnaissance, identify vulnerable internal systems, or bypass network segmentation, leading to deeper network compromise.

## Impact

Successful exploitation of CVE-2026-0285 could enable an authenticated administrator to bypass network segmentation controls, conduct internal network reconnaissance, or interact with sensitive internal services that would otherwise be inaccessible. While no malicious exploitation has been reported, this could lead to unauthorized information disclosure from internal systems, expose vulnerable internal services, or facilitate lateral movement within an organization's network. The risk of impact is significantly higher for organizations that do not adhere to best practices by exposing their PAN-OS management interfaces to untrusted networks or the internet.

## Recommendation

* Immediately patch CVE-2026-0285 by upgrading all affected PAN-OS instances to the recommended fixed versions listed in the advisory, such as PAN-OS 12.1.8+, 11.2.13+, 11.1.16+, or 10.2.18-h8+.
* Restrict management interface access to only trusted internal IP addresses, ensuring that external or untrusted networks cannot reach the PAN-OS management interface, as noted in the `Recommendation` section.
* For customers with a Threat Prevention subscription, enable Threat ID 510030 by updating to Applications and Threats content version 9122-10145 or later and ensure SSL Decryption is enabled for inbound traffic to management services.
* Review network configurations to confirm management interfaces are isolated and follow Palo Alto Networks' best practice deployment guidelines for securing administrative access.
