---
title: Denial of Service via Unvalidated Coinbase Height in Zebra (zebrad)
slug: 2026-10-zebrad-dos
description: An unvalidated coinbase height input in Zebra prior to 6.3.0 allows malicious peers to induce synchronization stalls and prevent nodes from reaching the latest chain tip.
date: "2026-10-02T12:24:07Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:zcashfoundation:zebra:*:*:*:*:*:*:*:*
vendors:
  - Zcash Foundation
products:
  - Zebra (< 6.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: A malicious peer can repeatedly serve a canonical block whose coinbase claims height 1 while keeping the requested hash, delaying the node's discovery of the newest block.
    confidence_band: high
cves:
  - id: CVE-2026-104422
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104422
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Zebra to version 6.3.0
      owner: IT Operations
      due: 48h
      evidence: Source states Zebra before 6.3.0 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade Zebra to version 6.3.0 or later
      owner: IT Operations
      addresses: CVE-2026-104422
      evidence: Source lists 6.3.0 as the fixed version
---

Zebra (zebrad) versions before 6.3.0 contain a vulnerability in the block sync download path that allows remote attackers to perform a Denial of Service (DoS) attack. The issue stems from the node reading a block's height directly from an unvalidated coinbase scriptSig. Because V5 transaction IDs in this protocol exclude the scriptSig, an attacker can manipulate the reported height in the coinbase while maintaining a canonical block hash. By serving blocks that claim an incorrect height (e.g., height 1) while requesting the latest chain tip, a malicious peer can force the target node to drop blocks that appear too far behind the current state. Crucially, the node fails to penalize the source of these invalid blocks, allowing the attacker to repeatedly stall the victim's synchronization progress and prevent the node from discovering the actual newest block on the network. This impacts the availability and consensus participation of affected nodes.

## Impact

The successful exploitation of CVE-2026-104422 results in a persistent denial-of-service condition for Zebra nodes. Affected nodes may fail to synchronize with the network, preventing them from validating or relaying transactions and blocks. This could lead to a loss of network participation and availability for services relying on Zebra, with potential impacts on transaction latency and node reliability within the Zcash ecosystem.

## Recommendation

- Upgrade Zebra (zebrad) to version 6.3.0 or later to ensure proper validation of block heights during synchronization.
- Monitor logs for repeated sync failures or blocks rejected due to height discrepancies from specific peer IP addresses.
- Implement network-level rate limiting or peer reputation management to identify and disconnect peers frequently transmitting invalid block data.
