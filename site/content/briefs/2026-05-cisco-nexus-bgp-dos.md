---
title: Cisco Nexus 3000 and 9000 Series Switches BGP Denial of Service Vulnerability
slug: 2026-05-cisco-nexus-bgp-dos
description: CVE-2026-20171 describes a vulnerability in the Border Gateway Protocol (BGP) enforce-first-as feature of Cisco Nexus 3000 and 9000 Series Switches that could allow an unauthenticated, remote attacker to trigger BGP peer flaps, resulting in a denial-of-service (DoS) condition.
date: "2026-05-20T16:02:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - bgp
  - dos
  - cisco
  - network
vendors:
  - Cisco
products:
  - Nexus 3000 Series Switches
  - Nexus 9000 Series Switches
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bgp-iefab-3hb2pwtx
  - CVE-2026-20171
rules:
  - title: Detect BGP Session Reset
    description: Detects a BGP session reset event, which could be indicative of a DoS attack (CVE-2026-20171).
    platform: sigma
    severity: low
    tactics:
      - denial_of_service
    techniques:
      - T1498
    data_sources:
      - firewall
  - title: Detect High Volume of BGP Updates
    description: Detects a high volume of BGP update messages, which could indicate a DoS attempt by flooding the network with crafted updates (CVE-2026-20171).
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1498
    data_sources:
      - network_connection
rules_count: 2
---

A vulnerability exists in the Border Gateway Protocol (BGP) enforce-first-as feature of Cisco Nexus 3000 Series Switches and Cisco Nexus 9000 Series Switches when operating in standalone NX-OS mode. Successful exploitation of this vulnerability could lead to a denial-of-service (DoS) condition. The vulnerability stems from the incorrect parsing of a transitive BGP attribute. Cisco has released software updates and workarounds to address this vulnerability.

## Attack Chain

1. An unauthenticated, remote attacker establishes a BGP peer session with a vulnerable Cisco Nexus switch.
2. The attacker crafts a malicious BGP update containing a malformed transitive BGP attribute.
3. The attacker sends the crafted BGP update to the targeted Cisco Nexus switch via the established BGP peer session.
4. The vulnerable switch attempts to parse the malformed transitive BGP attribute within the update.
5. Due to the incorrect parsing logic, the device experiences an error condition.
6. The device drops the BGP session with the peer that forwarded the update.
7. The BGP session repeatedly flaps (goes up and down) with the peer.
8. Continuous BGP session flapping results in a denial-of-service condition, disrupting network routing and connectivity.

## Impact

Successful exploitation of CVE-2026-20171 results in a denial-of-service condition, impacting the availability of network services. The affected Cisco Nexus switches, if exploited, will drop BGP sessions and flap with neighboring BGP peers, causing routing instability. This can lead to network outages and service disruptions.

## Recommendation

*   Apply the software updates released by Cisco to address CVE-2026-20171 on all affected Cisco Nexus 3000 Series and 9000 Series Switches to remediate the vulnerability.
*   Implement the workarounds provided by Cisco as a temporary mitigation measure if immediate patching is not feasible.
*   Monitor network traffic for unusual BGP update patterns that may indicate exploitation attempts, triggering the rules below to detect potential exploitation.
