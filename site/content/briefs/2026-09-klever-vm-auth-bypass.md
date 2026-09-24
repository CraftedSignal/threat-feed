---
title: Authorization Bypass in Klever-Go KleverUpdateAccountPermission Built-in
slug: 2026-09-klever-vm-auth-bypass
description: An authorization flaw in the Klever-Go VM allows attackers to execute an account takeover by leveraging an incorrectly validated RecipientAddr parameter during indirect smart contract calls.
date: "2026-09-23T19:57:00Z"
lastmod: "2026-09-24T01:57:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:klever:klever-go:*:*:*:*:*:*:*:*
tags:
  - blockchain
  - smart-contract
  - vulnerability
  - privilege-escalation
  - klever-go
  - log-manipulation
  - unauthenticated-access
  - websocket-vulnerability
  - consensus-failure
  - denial-of-service
  - blockchain-security
  - injection
  - elasticsearch
  - cve-2026-82409
vendors:
  - Klever
  - Elastic
products:
  - klever-go (<= 1.7.19)
  - Elasticsearch (< 1.7.20)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: 'The harm asserted is the takeover itself: after the call, V''s permission set is a single Owner permission whose sole signer is the attacker''s key.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The node processes the first message sent by the client as a logger 'Profile', which is applied globally.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: The protocol deserializes these keys at the start of each slot, an invalid key causes a deterministic failure in the multi-signature process, leading to a consensus failure and missed slots.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The attacker broadcasts an ordinary signed transaction to the blockchain.
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The attacker injects raw JSON/NDJSON syntax into the indexer's bulk stream, manipulating ES document state.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: The malicious payload is written into the consensus account state, ensuring it is re-indexed by current and future nodes.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-97cv-x867-6xhm
  - https://github.com/advisories/GHSA-9v8p-frvj-2pcm
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86064
  - https://github.com/advisories/GHSA-9wh6-9hq7-9688
  - https://github.com/advisories/GHSA-7c7c-373r-gfjj
rules:
  - title: Detect Unauthenticated WebSocket Log Profile Manipulation
    description: Detects exploitation of CVE-2026-86064 where an unauthenticated client sends a logging profile mutation payload to the /log endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Development
  immediate_actions:
    - action: Upgrade klever-go to the patched version as defined in the vendor advisory
      owner: Development
      due: 24h
      evidence: CVE-2026-82405 remediation
  mitigation_plan:
    - priority: immediate
      action: Patch code to validate caller address instead of recipient address
      owner: Development
      addresses: CVE-2026-82405
      evidence: Code walkthrough indicates incorrect variable usage in handler
updates:
  - at: "2026-09-23T19:57:14Z"
    level: L2
    summary: 'added detection rule: Detect Unauthenticated WebSocket Log Profile Manipulation'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-9v8p-frvj-2pcm
  - at: "2026-09-24T01:57:29Z"
    level: L1
    summary: added coverage for klever-go (<= 1.7.19)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-9wh6-9hq7-9688
  - at: "2026-09-24T01:57:38Z"
    level: L1
    summary: added coverage for klever-go (<= 1.7.19) +1 products
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-7c7c-373r-gfjj
---

A critical authorization vulnerability (CVE-2026-82405) exists in the `KleverUpdateAccountPermission` built-in function within the `klever-go` repository, affecting versions 1.7.19 and earlier. The vulnerability occurs because the function validates permissions against the `vmInput.RecipientAddr` field rather than the authenticated `vmInput.CallerAddr`. 

In the context of an indirect smart contract call via `ExecuteOnDestContext`, the `RecipientAddr` is determined by the destination contract's chosen `dest` argument, which an attacker can manipulate. Because most accounts are configured as their own signers by default, the permission check incorrectly returns `true` when the attacker specifies the target account as the recipient. This allows an attacker to overwrite the entire permission set of any target account with their own malicious keys, resulting in a full account takeover. The issue is restricted to calls originating from smart contracts, as the native transaction path correctly validates senders.

## Attack Chain

1. Attacker deploys a malicious smart contract to the blockchain.
2. Attacker initiates an `ExecuteOnDestContext` call from their malicious contract.
3. Attacker sets the `dest` argument to the victim account address (V).
4. The VM dispatch mechanism `prepareIndirectContractCallInput` sets `RecipientAddr` to V and `CallerAddr` to the attacker's contract.
5. The `KleverUpdateAccountPermission` handler receives the call and executes `contractHasValidPermission` using the attacker-controlled `RecipientAddr` (V).
6. The check compares V against V's own signers, which inherently grants permission for the Owner type.
7. The VM proceeds to `UpdatePermission`, replacing V's original account permissions with attacker-supplied signers.
8. Attacker gains full control over the victim account, enabling asset theft or account lock.

## Impact

Successful exploitation results in the complete compromise of any account with configured permissions on the Klever blockchain. Victims include multisig and advanced-permission accounts. Attackers can evict original owners and gain full control over all operations associated with the victim's address, leading to irreversible loss of funds or total account lockout.

## Recommendation

Patch the `KleverUpdateAccountPermission` handler to validate authorization against `vmInput.CallerAddr` instead of `vmInput.RecipientAddr`.
Update `klever-go` to a version containing the fix for CVE-2026-82405.
Review all smart contract built-in function handlers in the `klever-go` codebase for similar authorization discrepancies between `RecipientAddr` and `CallerAddr`.
Implement logic to require the target account address in `Arguments[0]` to match the authenticated caller or a legitimately authorized entity.
