---
title: Zebra Node Denial-of-Service Vulnerability via Crafted Orchard Transactions (CVE-2026-41584)
slug: 2026-05-zebra-dos
description: A crafted Orchard transaction with a zero-value rk field can cause a Zebra node to crash due to a panic in the orchard crate, leading to a denial-of-service condition; this vulnerability is identified as CVE-2026-41584 and patched in zebrad version 4.3.1 and zebra-chain version 6.0.2.
date: "2026-05-08T15:16:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:zfnd:zebra-chain:*:*:*:*:*:rust:*:*
  - cpe:2.3:a:zfnd:zebrad:*:*:*:*:*:rust:*:*
tags:
  - denial-of-service
  - zcash
  - cryptography
vendors:
  - ZFND
products:
  - zebra-chain
  - zebrad
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-41584
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41584
rules:
  - title: Detect CVE-2026-41584 Exploitation Attempt — Orchard Transaction with Zero Rk
    description: Detects CVE-2026-41584 exploitation attempt — monitors for orchard transactions with zero rk values
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - application
      - zebrad
rules_count: 1
---

ZEBRA is a Zcash node written entirely in Rust. Prior to the patched versions, a vulnerability existed within the handling of Orchard transactions. Specifically, the `rk` field, a randomized validating key and elliptic curve point within Orchard transactions, was not properly validated. The Zcash specification allows this field to be the identity (a "zero" value). However, the `orchard` crate, responsible for verifying Orchard proofs, would panic when processing an `rk` field with this identity value. An attacker could exploit this by sending a specially crafted transaction to a Zebra node, triggering the panic and causing the node to crash, leading to a denial-of-service condition. This issue is tracked as CVE-2026-41584 and has been addressed in `zebrad` version 4.3.1 and `zebra-chain` version 6.0.2.

## Attack Chain

1.  Attacker crafts a malicious Zcash transaction.
2.  The crafted transaction includes an Orchard transaction with a `rk` field set to the identity (zero) value.
3.  Attacker sends the crafted transaction to a vulnerable Zebra node.
4.  The Zebra node receives the transaction and attempts to verify the Orchard proof.
5.  The `orchard` crate within the Zebra node processes the `rk` field.
6.  Due to the zero value of the `rk` field, the `orchard` crate panics.
7.  The panic causes the Zebra node to crash.
8.  The Zebra node becomes unavailable, resulting in a denial-of-service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition for the affected Zebra node. An attacker can repeatedly send crafted transactions to disrupt the node's operation. While the vulnerability does not lead to data breach or arbitrary code execution, it can impact the availability of services relying on the Zebra node. The number of affected nodes depends on the adoption rate of vulnerable `zebrad` versions prior to 4.3.1.

## Recommendation

*   Upgrade all Zebra nodes running versions prior to 4.3.1 to version 4.3.1 or later to patch CVE-2026-41584.
*   Deploy the Sigma rule "Detect CVE-2026-41584 Exploitation Attempt — Orchard Transaction with Zero Rk" to detect attempts to exploit this vulnerability by monitoring transaction patterns.
