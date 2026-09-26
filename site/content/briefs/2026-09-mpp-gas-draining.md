---
title: ZenHive mpp Package Gas Draining and DoS Vulnerability
slug: 2026-09-mpp-gas-draining
description: The mpp Elixir package fails to validate client-supplied gas limits before broadcasting transactions as a fee-payer, allowing attackers to drain the server's wallet through repeated out-of-gas transaction failures.
date: "2026-09-26T02:07:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:zenhive:mpp:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - blockchain
  - elixir
  - vulnerability
vendors:
  - ZenHive
products:
  - mpp (>= 0.2.0, < 0.6.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker can spawn N malicious clients to completely drain the funds from the server's wallet to perform a Denial of Service (DoS) attack.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-vj8p-hp9x-gh47
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade mpp to version 0.6.0 or later.
      owner: Development
      due: 24h
      evidence: Source states affected versions are >= 0.2.0, < 0.6.0.
  mitigation_plan:
    - priority: immediate
      action: Upgrade mpp to version 0.6.0.
      owner: Development
      addresses: mpp (>= 0.2.0, < 0.6.0)
      evidence: GHSA-vj8p-hp9x-gh47
---

The mpp Elixir package (ZenHive/mpp), specifically versions 0.2.0 through 0.5.x, contains a critical vulnerability in its transaction broadcasting mechanism. When the server acts as the designated fee payer for client-initiated operations, it fails to validate whether the `gas_limit` provided by the client is sufficient to complete the transaction execution on the blockchain. 

An attacker can exploit this by crafting a transaction with a `gas_limit` slightly lower than the required threshold for a successful operation. The server cosigns and broadcasts the transaction, which subsequently fails during execution due to out-of-gas conditions. Despite the transaction failure and the resulting state revert, the server's fee-payer wallet is still charged for the consumed gas. Because the attacker does not pay for this execution, they can automate this process across multiple clients to drain the server's funds, effectively performing a denial-of-service attack that prevents legitimate users from processing transactions.

## Attack Chain

1. The attacker initializes a client instance capable of interacting with the mpp service.
2. The attacker identifies a target contract method that requires a known amount of gas (e.g., `transferWithMemo`).
3. The attacker constructs a transaction payload with a `gas_limit` set just below the threshold required for successful execution.
4. The attacker sends the malicious transaction payload to the mpp server, requesting the server to act as the fee-payer.
5. The server executes `broadcast_and_verify/7` in `mpp/methods/tempo.ex`, failing to perform a simulation or a minimum gas validation check before broadcasting.
6. The transaction is broadcast to the network; the EVM execution consumes the available gas and reverts.
7. The network charges the server's fee-payer wallet for the gas consumed during the failed execution.
8. The attacker repeats these steps to systematically deplete the server's wallet funds to achieve a permanent DoS state.

## Impact

Successful exploitation results in the financial depletion of the server's wallet, causing a complete denial-of-service for all legitimate users relying on that wallet to pay for transaction fees. The attack is highly impactful because it requires only compute resources from the attacker to initiate, rather than requiring the attacker to deposit their own funds, making it a zero-cost DoS vector against infrastructure providers.

## Recommendation

Prioritized actions for development and infrastructure teams using mpp:
- Upgrade the mpp package to version 0.6.0 or later to ensure proper gas limit validation before transaction broadcasting.
- Audit the `broadcast_and_verify/7` logic to ensure that `wait_for_confirmation = true` paths perform a pre-flight gas simulation using a robust, parameter-aware `eth_call`.
- Implement server-side rate limiting on transaction requests to prevent the rapid-fire submission of intentionally failing transactions from the same source.
- Implement monitoring for a high frequency of failed transactions originating from the same client ID or source IP, which may indicate an attempt to trigger this vulnerability.
