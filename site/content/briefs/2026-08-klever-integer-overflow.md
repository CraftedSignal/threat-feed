---
title: Integer Overflow in Klever Split-Royalty Validation Enables Unbounded Token Minting
slug: 2026-08-klever-integer-overflow
description: An integer overflow vulnerability in the Klever node (klever-go) allows attackers to mint arbitrary amounts of KLV and other assets by bypassing split-royalty validation checks.
date: "2026-08-28T21:13:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - integer-overflow
  - blockchain
  - financial-integrity
vendors:
  - Klever
products:
  - klever-go
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker uses the operator CLI to sign and broadcast malicious transactions to the unauthenticated /transaction/send endpoint.
    confidence_band: high
action_plan:
  priority: immediate_escalation
  owners:
    - Detection Engineering
    - Core Developers
  immediate_actions:
    - action: Patch klever-go validation logic to include per-entry bounds and uint64 accumulation
      owner: Core Developers
      due: 24h
      evidence: Source provides specific remediation requirements in 'Remediation' section.
---

The Klever blockchain node (klever-go) contains a critical integer overflow vulnerability in its split-royalty validation logic. The system decodes per-entry royalty percentages as `uint32` values without individual upper bounds and aggregates them into a `uint32` accumulator. By providing two split royalty entries that sum to a value exceeding 2^32, the accumulator wraps around to zero, successfully passing the 100% (10000) validation check.

During royalty payout, the system calculates payments using these massive overflowed values, crediting recipients with KLV far exceeding the original royalty pool. The negative remainder is silently discarded rather than returning an error, allowing the attacker to mint KLV or other assets out of thin air. This vulnerability is not gated by existing guards such as `FixMarketBuyOverflow` and remains exploitable on current mainnet deployments. Because the minted tokens are credited directly via balance modification rather than tracked mint events, the inflation remains invisible in official supply dashboards, posing a significant risk to the economic integrity of the ecosystem.

## Attack Chain

1. Attacker crafts a malicious KDA asset creation transaction using the `kloperator` tool.
2. The transaction includes two split-royalty recipients, each assigned a percentage value of 21474836.48.
3. The node processes these as raw `uint32` values (`2147483648`), causing the sum to wrap around to `0` in the `uint32` accumulator.
4. The `CheckValid100Params` function incorrectly validates the wrapped sum of `0` as permissible.
5. The attacker initiates a standard asset transfer or market buy, triggering the royalty payout logic.
6. The payout logic retrieves the overflowed `2147483648` percentage, calculating a massive credit for the recipient.
7. The `AddToBalance` function executes, crediting the recipient's wallet with inflated KLV or asset balances.
8. The system silently ignores the resulting negative remainder, finalizing the unauthorized mint.

## Impact

Successful exploitation results in the unbounded inflation of KLV and other assets. Because the inflation is handled via direct balance updates rather than tracked minting processes, the supply metrics appear accurate while the token value is eroded. This can lead to a total loss of economic integrity, affecting all holders within the Klever ecosystem. Any user with sufficient funds for transaction fees can exploit this without requiring administrative privileges.

## Recommendation

1. Implement per-entry bounds checking in `decodeSplitInfo` within `core/kapp/builtInFunctions/utils.go` to reject any individual percentage exceeding `HundredPercent` (10000).
2. Modify the validation logic in `core/kapp/kda/create.go` and `core/kapp/kda/trigger.go` to use `uint64` accumulators to prevent integer wrapping during the summation of royalty percentages.
3. Enforce these changes via a new activation-epoch fork flag to ensure historical blocks remain consistent while preventing future exploitation.
