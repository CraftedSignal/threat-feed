---
title: Denial of Service via Asymmetric Resource Consumption in Zebrad
slug: 2026-10-zebra-resource-exhaustion
description: Unauthenticated remote peers can exploit a vulnerability in Zebrad versions prior to 6.2.1 by submitting mempool transactions with invalid Halo2 proofs, leading to a denial-of-service condition.
date: "2026-10-02T14:24:44Z"
type: advisory
types:
  - advisory
severities:
  - low
cves:
  - id: CVE-2026-104423
    cvss: 7.5
---

Zebra (zebrad) versions before 6.2.1 are vulnerable to an asymmetric resource consumption vulnerability (CVE-2026-104423). This flaw allows unauthenticated remote peers to stall the block verification process by submitting specifically crafted mempool transactions. By flooding the node's shared, unprioritized Halo2 verification queue with zero-fee transactions that utilize zero-filled Orchard and Ironwood proofs, an attacker can consume significant node
