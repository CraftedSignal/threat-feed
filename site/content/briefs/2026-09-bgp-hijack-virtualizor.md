---
title: BGP Hijacking Campaign Targeting Virtualizor Software Updates
slug: 2026-09-bgp-hijack-virtualizor
description: An unidentified threat actor leveraged a 33-hour BGP hijack to intercept traffic and serve malicious updates for the Virtualizor web hosting platform via a spoofed update portal.
date: "2026-09-03T06:00:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain-attack
  - bgp-hijacking
  - software-update-tampering
vendors:
  - Softaculous
products:
  - Virtualizor
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: Supply Chain Compromise
    evidence: The hacker performed the BGP hijack... and hosted a clone website that delivered the malicious updates.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498.001
    technique_name: Network Denial of Service
    evidence: An unidentified threat actor has pulled off a successful BGP hijack that commandeered some of the IP address space and internet routing for software company Softacolous.
    confidence_band: high
references:
  - https://news.risky.biz/srsly-risky-biz-chinas-private-sector-botnets-are-worth-disrupting/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Network Engineering
  immediate_actions:
    - action: Review BGP routing history for anomalies during the late-August 2026 timeframe
      owner: Network Engineering
      due: 48h
      evidence: Source states BGP hijack lasted 33 hours from Friday to Sunday
  hunt_leads:
    - lead: Virtualizor update processes occurring between Aug 2026 Friday-Sunday window
      technique_id: T1195.002
      data_needed:
        - Process execution logs
        - Network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Hackers delivered malicious updates via cloned website
  mitigation_plan:
    - priority: immediate
      action: Enable RPKI route origin validation on edge routers
      owner: Network Engineering
      addresses: BGP Hijacking
      evidence: Successful BGP hijack facilitated the attack
---

During a 33-hour window in late August 2026, an unidentified threat actor conducted a BGP hijack against the infrastructure belonging to Softaculous, the vendor behind the Virtualizor web hosting management platform. By hijacking IP address space associated with the vendor, the attackers intercepted legitimate traffic intended for update servers. The threat actors successfully generated a fraudulent TLS certificate to present as the legitimate vendor, allowing them to host a cloned update portal and distribute malicious updates directly to Virtualizor users. The incident demonstrates a sophisticated supply-chain attack vector that bypasses traditional endpoint and network perimeter defenses by compromising the underlying internet routing fabric. The vendor has reported that the total impact remains unknown due to the lack of visibility into the traffic diverted through the attacker's infrastructure.

## Attack Chain

1. The threat actor performs reconnaissance on Softaculous/Virtualizor infrastructure to identify BGP prefixes and update server endpoints.
2. The actor initiates a BGP hijack (T1498.001) to commandeer the victim's IP space, redirecting traffic through attacker-controlled infrastructure.
3. The actor requests and obtains a fraudulent TLS certificate (T1588.003) for the domain names associated with Virtualizor update services.
4. A cloned update server is deployed on the hijacked IP range, mirroring the vendor's update portal.
5. Virtualizor systems checking for updates are transparently redirected to the malicious portal due to the BGP route manipulation.
6. Victim systems download and execute the malicious update package (T1195.002) delivered via the attacker's server.
7. The compromised hosts initiate outbound connections to attacker-controlled C2 infrastructure (T1071.001).

## Impact

The campaign compromised the update mechanism of the Virtualizor platform, a critical tool for web hosting management. The impact includes the potential for widespread remote code execution across thousands of hosted web environments. Because the traffic was intercepted at the network layer, the vendor lacked logs to identify the number of victims or the specific nature of the malicious payloads delivered.

## Recommendation

1. Audit BGP routing logs (e.g., from BGPStream or internal routers) for unauthorized advertisements or path changes involving Softaculous IP prefixes during the period of August 2026.
2. Review system logs on Virtualizor nodes for update activities occurring between the affected Friday and Sunday window to identify potential unauthorized binaries.
3. Implement RPKI (Resource Public Key Infrastructure) validation on network infrastructure to prevent unauthorized BGP origin advertisements.
4. Verify the certificate authority (CA) and serial number for TLS certificates associated with critical update endpoints to ensure they match expected, vendor-provided fingerprints.
