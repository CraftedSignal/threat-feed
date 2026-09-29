---
title: Denial-of-Service Vulnerability in Baicells Nova 430H eNodeB
slug: 2026-09-baicells-nova-430h-dos
description: An unauthenticated attacker within radio range can trigger a denial-of-service on the Baicells Nova 430H eNodeB by sending malformed NAS payloads during connection setup (CVE-2026-96274).
date: "2026-09-29T16:24:50Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - denial-of-service
  - ics
  - cve-2026-96274
vendors:
  - Baicells Technologies
products:
  - Nova 430H eNodeB (<=BaiBLQ_3.0.12)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Successful exploitation of this vulnerability could allow an attacker to inject malformed messages which may lead to a denial-of-service condition.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-272-04
  - https://www.cve.org/CVERecord?id=CVE-2026-96274
action_plan:
  priority: elevated
  owners:
    - SOC
    - Network Operations
  immediate_actions:
    - action: Review firewalls for unauthorized exposure of cellular core or eNodeB management interfaces
      owner: Network Operations
      due: 72h
      evidence: CISA recommends minimizing network exposure for all control system devices
  mitigation_plan:
    - priority: medium_term
      action: Contact Baicells support for guidance on CVE-2026-96274 as no patch is planned
      owner: IT Operations
      addresses: CVE-2026-96274
      evidence: Baicells has not responded to requests to work with CISA to mitigate this vulnerability
---

The Baicells Nova 430H eNodeB (model pBS3101SH), specifically versions up to and including BaiBLQ_3.0.12, is susceptible to a denial-of-service vulnerability tracked as CVE-2026-96274. The vulnerability arises from an uncaught exception (CWE-248) when the device fails to properly validate the Non-Access Stratum (NAS) payload within an uplink message during the initial connection setup process. An unauthenticated attacker within radio range of the device can exploit this by transmitting a malformed message. Upon receipt, the eNodeB inadvertently forwards the invalid payload to the core network, causing a collapse of the signaling association. This results in a persistent service disruption for the affected cell until connectivity is manually re-established between the eNodeB and the core. Baicells has not provided a patch or remediation plan for this issue.

## Attack Chain

1. The attacker positions themselves within the radio range of the targeted Baicells Nova 430H eNodeB.
2. The attacker initiates a connection request to the eNodeB using standard radio signaling protocols.
3. During the subsequent connection setup phase, the attacker crafts a malicious uplink NAS payload.
4. The attacker transmits the malformed payload to the eNodeB.
5. The eNodeB fails to validate the structure or contents of the received NAS payload.
6. The eNodeB forwards the invalid payload to the connected core network.
7. The core network rejects the signaling due to the malformed data, resulting in a shutdown of the signaling association.
8. The cell becomes unavailable, causing a denial-of-service for users attempting to connect to that base station.

## Impact

This vulnerability impacts critical infrastructure within the Communications and Information Technology sectors worldwide. A successful attack results in the loss of service for the targeted eNodeB, preventing legitimate users from accessing network connectivity. Given the nature of the device as a radio access point, the impact is focused on the availability of cellular services. There is no patch available for this vulnerability, and as of the reporting date, no active exploitation in the wild has been confirmed.

## Recommendation

1. Minimize exposure of control system devices by ensuring the eNodeB management interfaces are not accessible from the public internet.
2. Implement network segmentation by placing remote devices behind firewalls and isolating them from internal business networks.
3. Utilize encrypted VPN tunnels for all remote management access to the eNodeB infrastructure.
4. Review internal incident response procedures for handling localized denial-of-service events related to radio access network infrastructure.
5. Contact Baicells customer support for further information regarding potential configuration workarounds, as no firmware update is planned.
