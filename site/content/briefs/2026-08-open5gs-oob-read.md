---
title: Out-of-Bounds Read in Open5GS Rx AA-Request Handler
slug: 2026-08-open5gs-oob-read
description: Open5GS 2.8.0 contains an out-of-bounds read vulnerability in the pcrf_rx_aar_cb function that allows a remote attacker to potentially cause a service crash or information disclosure.
date: "2026-08-24T01:40:24Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - cve-2026-78157
  - denial-of-service
  - memory-corruption
products:
  - Open5GS (2.8.0)
cves:
  - id: CVE-2026-78157
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-78157
  - https://github.com/open5gs/open5gs/commit/c18dc6938bf63cc7374315d3dca303d92066e746
  - https://vuldb.com/vuln/394540
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Open5GS to the latest version containing the patch for CVE-2026-78157
      owner: IT Operations
      due: 72h
      evidence: Patch is available in commit c18dc6938bf63cc7374315d3dca303d92066e746
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the PCRF interface
      owner: IT Operations
      addresses: CVE-2026-78157
      evidence: The attack is initiated remotely over the network
---

A memory safety vulnerability has been identified in Open5GS 2.8.0, specifically within the Rx AA-Request Handler component. The vulnerability is located in the `pcrf_rx_aar_cb` function within `src/pcrf/pcrf-rx-path.c`. An unauthenticated remote attacker can trigger this vulnerability by sending a maliciously crafted AA-Request (AAR) packet to the PCRF (Policy and Charging Rules Function) interface. Successful exploitation results in an out-of-bounds memory read, which can be leveraged to crash the service, leading to a denial-of-service condition, or potentially leak sensitive information from the process memory. The vendor has released a patch in commit `c18dc6938bf63cc7374315d3dca303d92066e746`. Organizations running Open5GS 2.8.0 should prioritize updating to the patched version.

## Attack Chain

1. The attacker identifies an internet-facing or reachable Open5GS PCRF interface.
2. The attacker crafts a malicious Diameter AA-Request (AAR) packet.
3. The attacker transmits the packet to the PCRF component.
4. The `pcrf_rx_aar_cb` function processes the incoming AAR request.
5. The function fails to properly validate memory bounds during the packet parsing process.
6. An out-of-bounds read occurs, accessing memory outside the intended buffer.
7. The application encounters a memory error or continues execution using corrupted data.
8. The service crashes or discloses memory contents to the attacker.

## Impact

Successful exploitation of this vulnerability in an Open5GS deployment could lead to a localized denial of service for the core network control plane or the unauthorized exposure of process memory contents. Given that Open5GS is a critical component for 5G core network operations, such disruptions can impact network availability and subscriber connectivity.

## Recommendation

- Upgrade all instances of Open5GS 2.8.0 to a patched version using the fix provided in commit `c18dc6938bf63cc7374315d3dca303d92066e746`.
- Implement network-level access control lists (ACLs) to restrict access to the PCRF interface to trusted entities only.
- Monitor logs for repeated service restarts of the Open5GS PCRF component which may indicate active exploitation attempts.
