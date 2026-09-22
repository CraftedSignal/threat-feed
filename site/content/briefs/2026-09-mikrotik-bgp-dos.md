---
title: 'CVE-2026-93345: Improper Input Validation in MikroTik RouterOS BGP Service'
slug: 2026-09-mikrotik-bgp-dos
description: An unauthenticated, on-path attacker can trigger a denial-of-service condition in MikroTik RouterOS by sending malformed BGP UPDATE packets with out-of-bounds prefix-lengths.
date: "2026-09-22T18:39:23Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:mikrotik:routeros:*:*:*:*:*:*:*:*
vendors:
  - MikroTik
products:
  - RouterOS (< 7.25beta4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: 'Endpoint Denial of Service: OS Exhaustion'
    evidence: Attackers can repeatedly send a single BGP UPDATE packet carrying a VPNv4 or VPNv6 NLRI with an out-of-bounds prefix-length to indefinitely hold down the BGP plane, causing session termination without a NOTIFICATION and triggering a service malfunction on the device.
    confidence_band: high
cves:
  - id: CVE-2026-93345
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93345
action_plan:
  priority: elevated
  owners:
    - Network Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade MikroTik RouterOS to version 7.25beta4 or later.
      owner: Network Operations
      addresses: CVE-2026-93345
      evidence: MikroTik RouterOS before 7.25beta4 contains an improper input validation vulnerability.
---

MikroTik RouterOS versions prior to 7.25beta4 contain an improper input validation vulnerability within the labelled-VPN NLRI iterators of the BGP routing service. This flaw allows an unauthenticated, on-path attacker to send a malformed MP_REACH_NLRI UPDATE message containing a prefix-length value that is below the minimum required for a valid labelled-VPN NLRI. Because the router fails to properly validate this value, it interprets the packet as describing a route with a negative-length address portion, leading to a service crash. Attackers can leverage this by repeatedly sending a single BGP UPDATE packet containing a VPNv4 or VPNv6 NLRI with an out-of-bounds prefix-length to cause indefinite BGP plane instability and repeated session terminations, effectively creating a persistent denial-of-service (DoS) condition on the affected device.

## Impact

Successful exploitation results in a persistent denial-of-service condition, rendering the BGP service on the targeted MikroTik device unstable or non-functional. This impacts network routing availability for any traffic relying on the BGP session handled by the vulnerable process.

## Recommendation

Prioritize the identification of internet-facing or peer-connected MikroTik devices. Upgrade all affected instances of RouterOS to version 7.25beta4 or later to address the input validation flaw identified in CVE-2026-93345.
