---
title: Denial of Service in ZcashFoundation Zebra Node
slug: 2026-10-zebra-dos
description: A vulnerability in ZcashFoundation Zebra 6.4.0 and 6.4.1 allows unauthenticated remote attackers to crash the node by sending a crafted version 6 transaction with a pre-NU6.3 consensus branch ID.
date: "2026-10-12T18:38:22Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:zcashfoundation:zebra:6.4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:zcashfoundation:zebra:6.4.1:*:*:*:*:*:*:*
vendors:
  - ZcashFoundation
products:
  - Zebra (6.4.0-6.4.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Unauthenticated peers can send a single pre-handshake tx message to crash the node, and can repeat this after each restart.
    confidence_band: high
cves:
  - id: CVE-2026-109363
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109363
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Zebra to version 6.4.2 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109363 remediation requires update to 6.4.2.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Zebra to 6.4.2
      owner: IT Operations
      addresses: CVE-2026-109363
      evidence: Source explicitly identifies version 6.4.2 as the fixed release.
---

ZcashFoundation Zebra versions 6.4.0 through 6.4.1 contain a denial-of-service vulnerability arising from improper error handling during the processing of specific transaction types. The issue occurs when the node parses a version 6 transaction that carries a pre-NU6.3 consensus branch ID. During the construction of an UnminedTx, the size computation logic assumes that the re-serialization of the Orchard bundle is always successful. If this assumption fails, the application triggers an assertion error, which results in an immediate crash of the zebrad process. Because this message can be sent by unauthenticated peers as a pre-handshake transaction, remote attackers can persistently crash the node by repeatedly sending the malicious payload after every restart, effectively disrupting the availability of the Zebra node on the Zcash network.

## Impact

The vulnerability allows for trivial, persistent denial-of-service attacks against Zebra nodes running vulnerable versions. By sending a single crafted packet, an attacker can crash the node. If the service is automatically restarted by a manager, the attacker can repeat the attack indefinitely, preventing the node from participating in network consensus and processing transactions. This impact is critical for operators of Zebra nodes who rely on consistent uptime for network synchronization and verification.

## Recommendation

- Upgrade all instances of ZcashFoundation Zebra to version 6.4.2 or later to include the mandatory error handling fix for Orchard bundle re-serialization.
- Monitor network logs for a high frequency of incoming 'tx' messages followed immediately by zebrad service termination or restart events.
- Patch CVE-2026-109363 across all Zebra node infrastructure immediately.
