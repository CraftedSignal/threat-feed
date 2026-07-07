---
title: dhcpcd Denial of Service Vulnerability
slug: 2026-07-dhcpcd-dos
description: A vulnerability in the dhcpcd DHCP client daemon allows an attacker from an adjacent network to execute a Denial of Service attack, potentially disrupting network connectivity on affected Linux systems.
date: "2026-07-06T09:51:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - linux
  - impact
vendors:
  - dhcpcd
products:
  - dhcpcd
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: Ein Angreifer aus einem angrenzenden Netzwerk kann eine Schwachstelle in dhcpcd ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2195
---

The German Federal Office for Information Security (BSI) has issued an advisory regarding a denial-of-service vulnerability affecting the dhcpcd DHCP client daemon. This vulnerability allows an attacker operating from an adjacent network segment to disrupt the normal operation of systems running dhcpcd. Specifically, the flaw could lead to a Denial of Service (DoS) attack, rendering affected Linux machines unable to obtain or renew IP addresses, thus losing network connectivity. This issue highlights the importance of securing network infrastructure components, even those seemingly low-level like DHCP clients, as their compromise can have cascading effects on critical systems. Defenders need to prioritize patching dhcpcd instances, especially on servers or critical workstations, and implement network segmentation to limit the blast radius of such adjacent-network attacks. The advisory, identified as WID-SEC-2026-2195, was published on July 6, 2026.

## Attack Chain

[The provided intelligence does not contain enough specific, technical details about the attack steps (e.g., specific packet types, exploit payloads, process names) to construct a detailed 6-8 step attack chain.]

## Impact

Successful exploitation of this dhcpcd vulnerability results in a Denial of Service, primarily affecting the network connectivity of the targeted Linux system. Machines relying on dhcpcd for IP address assignment would be unable to communicate on the network, effectively taking them offline. For critical servers, this could lead to significant downtime, loss of data access, and disruption of business operations. The attacker's proximity to the target on an adjacent network segment means that internal network segmentation is crucial for containing the impact and preventing such attacks from affecting critical infrastructure.

## Recommendation

*   Apply available patches or updates for the `dhcpcd` DHCP client daemon to address the Denial of Service vulnerability, as this directly remediates the identified flaw.
*   Implement stringent network segmentation to isolate critical systems running `dhcpcd` from untrusted adjacent networks, thereby limiting the attack surface described in this brief.
