---
title: 'CVE-2026-0280 PAN-OS: IPv6 Firewall Policy Bypass'
slug: 2026-07-pan-os-ipv6-firewall-bypass
description: An unauthenticated attacker can exploit CVE-2026-0280, an IPv6 packet processing vulnerability in the dataplane of Palo Alto Networks PAN-OS software, to bypass firewall security policy enforcement, allowing network traffic that should be blocked to reach protected services.
date: "2026-07-08T16:15:08Z"
type: threat
types:
  - threat
severities:
  - low
exploited: true
tags:
  - palo-alto-networks
  - firewall
  - vulnerability
  - ipv6
  - policy-bypass
  - cve
vendors:
  - Palo Alto Networks
products:
  - PAN-OS (12.1)
  - PAN-OS (11.2)
  - PAN-OS (11.1)
  - PAN-OS (10.2)
  - Prisma Access (11.2.0)
  - Prisma Access (10.2.0)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: An IPv6 packet processing vulnerability in the dataplane of Palo Alto Networks PAN-OS® software enables an unauthenticated attacker to bypass firewall security policy enforcement, allowing network traffic that should be blocked to reach protected services.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0280
---

Palo Alto Networks has disclosed CVE-2026-0280, an IPv6 packet processing vulnerability within the dataplane of PAN-OS® software, affecting versions 12.1, 11.2, 11.1, and 10.2, as well as Prisma Access 11.2.0 and 10.2.0. This flaw allows an unauthenticated attacker to bypass established firewall security policies, enabling network traffic that should otherwise be blocked to reach internal protected services. The vulnerability, described as CWE-131 (Incorrect Calculation of Buffer Size), requires IPv6 to be enabled on at least one interface of the affected firewall for exposure. There is currently no evidence of active exploitation in the wild, and Cloud NGFW and Panorama products are not impacted. This vulnerability matters for defenders as it can compromise network segmentation and expose internal assets to unauthorized access.

## Attack Chain

1. An unauthenticated remote attacker identifies a vulnerable Palo Alto Networks PAN-OS firewall with IPv6 enabled on at least one interface.
2. The attacker crafts a specially designed or malformed IPv6 packet, exploiting an underlying "Incorrect Calculation of Buffer Size" (CWE-131) vulnerability.
3. The crafted IPv6 packet is sent from the internet towards the external interface of the vulnerable PAN-OS firewall.
4. During the dataplane processing of this malicious IPv6 packet, the PAN-OS software fails to correctly apply the configured security policies.
5. The firewall erroneously permits the IPv6 packet to bypass rules that should block it, allowing it to traverse the firewall's perimeter.
6. The malicious traffic reaches internal network segments and protected services that were intended to be isolated by the firewall.
7. The attacker achieves unauthorized access to internal network resources, potentially leading to further reconnaissance, data exfiltration, or lateral movement.

## Impact

This vulnerability can lead to unauthorized network access, as traffic that should be explicitly blocked by firewall policies is permitted to reach protected services. While the CVSS-B score indicates a low impact on confidentiality and integrity, the bypass could expose internal systems to attack, potentially leading to sensitive data exposure or compromise of internal infrastructure. The primary impact is the subversion of network segmentation controls, allowing attackers to access resources that were previously thought to be secured. Palo Alto Networks is not aware of any malicious exploitation of this issue.

## Recommendation

* Upgrade affected PAN-OS devices immediately to a patched version as specified in the CVE-2026-0280 advisory (e.g., upgrade PAN-OS 12.1 < 12.1.4-h8 to 12.1.4-h8 or later).
* Apply the necessary updates to Prisma Access versions if they are still vulnerable, referencing CVE-2026-0280 for specific upgrade paths.
* As a temporary mitigation if immediate upgrade is not feasible, enable the "Non SYN TCP Reject" setting via the command `set deviceconfig setting session tcp-reject-non-syn yes` as described in the CVE-2026-0280 advisory.
