---
title: Zebra Block Validator Sigops Undercount Vulnerability
slug: 2026-05-zebra-sigops-undercount
description: Zebra's block validator undercounts signature operations, allowing it to accept invalid blocks, leading to a network split between Zebra and zcashd nodes.
date: "2026-05-07T20:54:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - blockchain
  - consensus-failure
  - zcash
vendors:
  - ZcashFoundation
products:
  - zebra ( < 4.4.0)
references:
  - https://github.com/advisories/GHSA-jv4h-j224-23cc
  - https://github.com/ZcashFoundation/zebra/releases/tag/v4.4.0
  - https://github.com/zcash/zips/issues/568
  - https://github.com/zcash/zcash/blob/v6.11.0/src/main.cpp#L826-L836
  - https://github.com/zcash/zcash/blob/v6.11.0/src/main.cpp#L840-L852
rules:
  - title: Detect High Coinbase ScriptSig Length
    description: Detects blocks with abnormally long coinbase scriptSig, potentially indicating an attempt to exploit the Zebra sigops undercount vulnerability CVE-2026-44498.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - firewall
      - zeek
  - title: Detect High Number of P2SH Spends in Block
    description: Detects blocks containing a high number of P2SH spends, potentially indicating an attempt to exploit the Zebra sigops undercount vulnerability CVE-2026-44498 related to aggregate P2SH sigops.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - firewall
      - zeek
rules_count: 2
---

Zebra, a Zcash node implementation, contains a critical vulnerability where its block validator incorrectly calculates the number of signature operations (sigops) within a block. This flaw, present in versions prior to 4.4.0, stems from two distinct undercounting issues: incorrect handling of coinbase transactions and P2SH scripts. An attacker, typically a malicious miner, can exploit this to create blocks that Zebra accepts but `zcashd` rejects. This discrepancy leads to a consensus failure, causing a network split where Zebra nodes follow a different, invalid chain. This vulnerability poses a significant risk to network integrity for operators relying on Zebra for consensus.

## Attack Chain

1. A malicious miner crafts a block with a high number of signature operations.
2. The miner hides sigops in the coinbase `scriptSig` (up to ~98 sigops).
3. The miner includes transactions with a high number of P2SH spends whose redeem scripts collectively exceed 20000 sigops.
4. Zebra's block validator undercounts sigops due to the coinbase scriptSig and P2SH redeem script handling issues.
5. Zebra accepts the invalid block because the sigop count is below `MAX_BLOCK_SIGOPS`.
6. `zcashd` rejects the block due to accurately counting the excessive sigops.
7. Zebra nodes build on the invalid block, diverging from the main Zcash chain followed by `zcashd` nodes.
8. A network split occurs, where Zebra and `zcashd` nodes operate on separate chains.

## Impact

The vulnerability results in a network split between Zebra and `zcashd` nodes. Zebra nodes may accept and propagate blocks that are considered invalid by the rest of the network, leading to transaction rollbacks and unpredictable behavior for users relying on Zebra for consensus. This could lead to a denial of service and financial losses for users of Zebra nodes. There is no information available regarding the number of victims or specific sectors targeted.

## Recommendation

*   Upgrade Zebra nodes to version 4.4.0 or later to patch the vulnerability as advised by the vendor.
*   Monitor network consensus and validate Zebra's chain against other Zcash implementations (`zcashd`) to detect potential forks caused by this vulnerability.
*   Consider deploying network-level rules to identify blocks with unusually large coinbase `scriptSig` fields.
*   Enable detailed logging for block validation processes in Zebra to investigate potential consensus failures.
