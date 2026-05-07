---
title: Zebra Consensus Divergence in Transparent Sighash Hash-Type Handling (CVE-2026-44497)
slug: 2024-01-09-zebra-consensus-divergence
description: Zebra versions prior to 4.4.0 exhibit a consensus divergence vulnerability (CVE-2026-44497) due to insufficient error handling of invalid sighash types during sighash computation, potentially leading to network partitioning and double-spend attacks.
date: "2026-05-07T20:56:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - consensus-failure
  - vulnerability
  - network-partition
vendors:
  - ZcashFoundation
products:
  - zebrad
  - zebra-script
references:
  - https://github.com/advisories/GHSA-gq4h-3grw-2rhv
rules:
  - title: Detect CVE-2026-44497 Exploitation Attempt - Sighash Type Validation Failure
    description: Detects potential exploitation attempts of CVE-2026-44497 by monitoring for transactions containing scripts with undefined sighash types processed by vulnerable Zebra nodes. This rule looks for error messages indicating sighash validation failures, suggesting an attacker is attempting to trigger the consensus split.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - resource_development
    techniques:
      - T1078
      - T1588.006
    data_sources:
      - application
      - zebrad
  - title: Detect CVE-2026-44497 Exploitation Attempt - High Rate of Invalid Transactions
    description: Detects potential exploitation attempts of CVE-2026-44497 by monitoring for Zebra nodes that are processing and rejecting a high rate of transactions due to signature validation failures. This can indicate an attacker is sending specially crafted transactions to exploit the consensus divergence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - resource_development
    techniques:
      - T1078
      - T1588.006
    data_sources:
      - application
      - zebrad
rules_count: 2
---

Zebra, a Zcash node implementation, versions prior to 4.4.0 are vulnerable to a critical consensus divergence issue. This flaw, identified as CVE-2026-44497, stems from inadequate error handling when processing invalid sighash types during signature hash computation. Specifically, when an undefined hash type is encountered, Zebra's foreign function interface (FFI) does not properly propagate the error from the Rust-based sighash computation callback to the C++ verification code. Consequently, the C++ checker may use a stale digest from a previous valid signature validation, leading to the acceptance of invalid transactions. This discrepancy can create a consensus split between Zebra and zcashd nodes, potentially disrupting the Zcash network. The vulnerability was introduced as a side effect of a previous fix (GHSA-8m29-fpq5-89jj).

## Attack Chain

1.  Attacker crafts a malicious transaction.
2.  Transaction contains a transparent output.
3.  The output is spent by a script that includes `OP_CHECKSIGVERIFY` and `OP_CHECKSIG`.
4.  `OP_CHECKSIGVERIFY` is executed with a valid hash type, priming the C++ sighash buffer with a valid digest.
5.  `OP_CHECKSIG` is executed with an undefined hash type.
6.  Zebra's Rust callback returns `None` due to the undefined hash type, but the C++ checker does not receive this signal.
7.  The C++ checker verifies the invalid signature against the stale digest in the buffer.
8.  Zebra incorrectly accepts the spend, while zcashd rejects it, leading to a consensus split.

## Impact

The vulnerability can lead to a consensus failure within the Zcash network. An attacker can exploit this to cause network partitioning, where different nodes have conflicting views of the blockchain's state. This can lead to service disruption for users relying on affected Zebra nodes. Furthermore, the vulnerability could potentially be exploited for double-spend attacks if a malicious miner relies on Zebra's faulty validation results. While the impact is mitigated by the prevalence of `zcashd` among miners, any miner or template pipeline relying on Zebra's validation is at risk.

## Recommendation

*   Upgrade all Zebra nodes to version 4.4.0 or later immediately to address CVE-2026-44497.
*   Monitor Zebra node logs for unexpected consensus errors or forks following the upgrade.
*   Evaluate the feasibility of implementing custom monitoring to detect divergence between Zebra and zcashd validation results within your environment.
