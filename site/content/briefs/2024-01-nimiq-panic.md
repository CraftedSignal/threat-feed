---
title: Nimiq Node Panic due to Invalid BLS Key
slug: 2024-01-nimiq-panic
description: An unauthenticated peer can crash a Nimiq node by sending a malformed election macro block containing an invalid BLS voting key, leading to a denial of service.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - nimiq
  - bls
vendors:
  - Nimiq
products:
  - nimiq-primitives
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-7c4j-2m43-2mgh
  - https://github.com/nimiq/core-rs-albatross/commit/e10eaebcd7774e5da6d0ff5e88ed13503474f0ff
  - https://github.com/nimiq/core-rs-albatross/releases/tag/v1.3.0
rules:
  - title: Detect Nimiq Node Panic - Invalid BLS Key Attempt
    description: Detects attempts to crash Nimiq nodes by sending election macro blocks with invalid BLS keys. This rule triggers when a node logs an error related to BLS key uncompression failure, indicating a potential DoS attack.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - application
      - nimiq
  - title: Detect Nimiq Node Panic - Election Macro Block Processing Error
    description: Detects errors during the processing of election macro blocks in Nimiq nodes. This could indicate a variety of issues, including invalid data that may trigger panics.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - application
      - nimiq
rules_count: 2
---

A critical vulnerability exists in Nimiq's core-rs-albatross library, specifically within the nimiq-primitives crate, affecting versions 0.2.0 and earlier. An attacker can exploit this vulnerability by sending a malicious election macro block to a Nimiq node. This block contains an invalid compressed BLS voting key. When the node attempts to process this block, specifically during the hashing of the election macro header and the validation of the validators set via `Validators::voting_keys()`, the `validator.voting_key.uncompress().unwrap()` function is triggered. Due to the invalid BLS key, this operation results in a panic, effectively crashing the Nimiq node and causing a denial-of-service condition. The vulnerability was patched in version 1.3.0 of the core-rs-albatross library.

## Attack Chain

1.  Attacker identifies a vulnerable Nimiq node running a version of `nimiq-primitives` less than or equal to 0.2.0.
2.  Attacker crafts a malicious election macro block.
3.  The malicious block contains an invalid compressed BLS voting key within the `validators` set.
4.  The attacker sends the crafted block to the target Nimiq node via the peer-to-peer network.
5.  The Nimiq node receives the block and begins processing it.
6.  During the hashing of the election macro header, the `validators` set is processed.
7.  The `Validators::voting_keys()` function is called, which attempts to uncompress the BLS voting key.
8.  Due to the invalid compressed BLS key, the `validator.voting_key.uncompress().unwrap()` function panics, causing the node to crash and leading to a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition for the targeted Nimiq node. This can disrupt network operations, prevent legitimate transactions from being processed, and potentially impact the overall stability of the Nimiq network. The vulnerability allows any untrusted peer to trigger the crash.

## Recommendation

*   Upgrade to version 1.3.0 or later of the `core-rs-albatross` library to patch CVE-2026-34065.
*   Implement rate limiting on incoming peer connections to mitigate the impact of malicious blocks being sent to the node.
