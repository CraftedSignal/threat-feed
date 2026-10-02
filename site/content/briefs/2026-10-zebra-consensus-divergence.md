---
title: Consensus Divergence Vulnerability in Zebra zebrad and zebra-script
slug: 2026-10-zebra-consensus-divergence
description: An incorrect signature operation count in Zebra zebrad 4.5.0 and zebra-script 7.0.0 causes consensus divergence when processing specific P2SH multisig transactions, potentially leading to a denial-of-service condition for affected nodes.
date: "2026-10-02T12:24:19Z"
lastmod: "2026-10-02T12:24:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - consensus-vulnerability
  - denial-of-service
  - zebra
  - blockchain
  - crypto
  - network-protocol
vendors:
  - Zebra
products:
  - zebrad (4.5.0)
  - zebra-script (7.0.0)
  - zebrad (4.4.0)
  - zebra-script (6.0.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Attackers can broadcast crafted V5 transactions with more inputs than outputs that Zebra accepts but zcashd rejects, causing a network consensus split.
    confidence_band: high
cves:
  - id: CVE-2026-104430
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104430
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104435
action_plan:
  priority: elevated
  owners:
    - Infrastructure Operations
    - Security Operations
  immediate_actions:
    - action: Inventory all systems running zebrad 4.5.0 or zebra-script 7.0.0
      owner: Infrastructure Operations
      due: 24h
      evidence: Source identifies specific vulnerable versions
  mitigation_plan:
    - priority: immediate
      action: Upgrade to patched versions immediately upon release
      owner: Infrastructure Operations
      addresses: CVE-2026-104430
      evidence: Consensus divergence leads to node stalling
updates:
  - at: "2026-10-02T12:24:33Z"
    level: L1
    summary: added coverage for zebrad (4.4.0) +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104435
---

Zebra zebrad version 4.5.0 and zebra-script version 7.0.0 contain a critical consensus vulnerability related to how signature operations (sigops) are calculated in P2SH redeem scripts. The software incorrectly uses legacy counting modes instead of the accurate P2SH mode employed by zcashd. Specifically, the implementation overcounts CHECKMULTISIG operations when preceded by OP_1 through OP_16, assigning them a value of 20 sigops. This discrepancy leads to a consensus divergence where Zebra nodes calculate a higher total sigop count for certain transactions than the zcashd reference implementation. This vulnerability allows remote attackers to construct and broadcast specific P2SH multisig spends that exceed Zebra's MAX_BLOCK_SIGOPS threshold while remaining valid within the zcashd network. Consequently, affected Zebra nodes will reject legitimate blocks and stall, effectively removing them from the consensus chain and creating a denial-of-service condition for the node.

## Impact

Successful exploitation of this vulnerability results in a denial of service for Zebra-based nodes. By broadcasting specifically crafted P2SH transactions, an attacker can force affected nodes to drop out of the network synchronization process, leading to loss of consensus and node stalling. This affects any network deployments relying on these specific versions of Zebra zebrad or zebra-script for block validation.

## Recommendation

Prioritize the identification of nodes running vulnerable Zebra software versions. Monitor node logs for repeated block validation failures or synchronization stalls that coincide with unusual multisig transaction activity. Upgrade affected systems to patched versions as soon as they are made available by the maintainers. Review network telemetry for anomalous block broadcast traffic targeting Zebra nodes.
