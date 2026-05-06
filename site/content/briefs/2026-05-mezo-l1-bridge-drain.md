---
title: Mezo L1 Bridge Vulnerability Leads to Potential ERC-20 Drain
slug: 2026-05-mezo-l1-bridge-drain
description: A vulnerability in the Mezo bridge allows for the potential full drain of the L1 bridge without changing the bridged balance on Mezo due to a stale StateDB overwrite, enabling a malicious user to steal ERC-20 tokens locked in the L1 bridge.
date: "2026-05-06T19:57:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - blockchain
  - smart-contract
  - bridge
  - state-overwrite
vendors:
  - Ethereum
products:
  - MezoBridge
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-6447-269v-g68m
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/x/evm/statedb/statedb.go#L677-L684
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/x/evm/statedb/statedb.go#L655-L674
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/x/evm/statedb/state_object.go#L236-L244
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/precompile/contract.go#L228
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/precompile/contract.go#L254-L265
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/precompile/assetsbridge/bridge_out.go#L141-L152
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/precompile/assetsbridge/bridge_out.go#L221-L222
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/x/evm/keeper/call.go#L19-L62
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/x/evm/keeper/state_transition.go#L390
  - https://github.com/mezo-org/mezod/blob/17af5fdf29a6884d52e5ba6a1ee788c1f6e2a5ab/x/bridge/keeper/assets_unlocked.go#L104-L163
rules:
  - title: Monitor Mezo Bridge ERC-20 Burn Events
    description: Detects calls to the burnERC20 function within the Mezo bridge contract, which could indicate potential exploitation of the stale StateDB overwrite vulnerability.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect AssetsUnlocked Event on Mezo Bridge
    description: Detects the occurrence of the AssetsUnlocked event on the Mezo bridge contract, indicating a potential transfer of assets to L1. This rule helps monitor for unusual activity related to asset unlocks, especially when paired with other suspicious behaviors.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect Transfer After burnERC20 Within Same Transaction
    description: Detects a transfer function call occurring in the same transaction after burnERC20 is called. This will assist in identifying possible exploits.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - webserver
      - linux
rules_count: 3
---

A critical vulnerability in the Mezo bridge allows a malicious actor to potentially drain all ERC-20 tokens locked in the Layer 1 (L1) bridge without affecting the bridged balance on the Mezo network. This attack exploits an asymmetry in how the `bridgeOut` precompile handles BTC and ERC-20 tokens. The vulnerability exists because the outer StateDB overwrites the inner burn transaction with stale values. This restores the attacker's balance and allowance while the `AssetsUnlocked` event has already been persisted to the bridge store. The Ethereum sidecar then observes this event, attests the unlock on L1, and releases real tokens to the attacker, who can repeat the drain every block. This issue was found in the Mezo EVM and impacts ERC-20 token bridging. The fixed version of the validator client has been deployed.

## Attack Chain

1. The attacker deploys a crafted contract on the Mezo network to interact with the `bridgeOut` precompile.
2. The attacker calls the `bridgeOut` precompile with an ERC-20 token, triggering the `burnERC20` function via `ExecuteContractCall`. This creates an inner StateDB where the token burn occurs.
3. Within the inner StateDB, the `burnFrom` function decreases the balance, supply, and allowance slots of the ERC-20 token.
4. The inner StateDB commits its changes to a cached context (`cachedCtx`) but does not propagate these changes to the outer StateDB's `dirtyStorage`.
5. The attacker triggers a `transfer(sink, 1)` in the same transaction, causing the outer StateDB to load the stale pre-burn balance from the base context (`baseCtx`).
6. The outer StateDB's `dirtyStorage` now contains the pre-burn allowance and stale balance, while the `AssetsUnlockedEvent` has been persisted to the bridge module's KV store.
7. During the `StateDB.Commit()` process, the stale allowance and balance slots in `dirtyStorage` overwrite the zeroed-out values from the inner burn, effectively erasing the burn.
8. The Ethereum sidecar observes the `AssetsUnlockedEvent` and calls `AttestBridgeOut` on the L1 MezoBridge contract, releasing real tokens to the attacker's L1 address. The attacker repeats this process per block to drain the bridge.

## Impact

This vulnerability poses a critical risk to the Mezo bridge, potentially leading to the theft of approximately $1,753,958.4 USD worth of assets held on the L1 bridge. Attackers can repeatedly exploit this vulnerability to drain ERC-20 tokens, including cbBTC, T, USDC, USDT, xSolvBTC, SolvBTC, FunctionBTC, USDe, swBTC, and DAI, without affecting their Mezo balance. This exploit threatens the integrity and trustworthiness of the Mezo bridge and the assets locked within it.

## Recommendation

*   Implement detection rules to identify transactions interacting with the `bridgeOut` precompile and `ExecuteContractCall` that do not properly propagate state changes to the outer StateDB.
*   Monitor Ethereum L1 MezoBridge contract (0xF6680EA3b480cA2b72D96ea13cCAF2cFd8e6908c) for unexpected or anomalous withdrawal patterns.
*   Investigate all `AssetsUnlockedEvent` events to validate that corresponding balance and allowance changes have been correctly applied within the Mezo network before attesting unlocks on L1 as described in `x/bridge/keeper/assets_unlocked.go:104-163`.
*   Enable logging of state changes within the EVM, particularly focusing on the `Commit()` function at `x/evm/statedb/statedb.go:677-684` to detect potential stale overwrites.
