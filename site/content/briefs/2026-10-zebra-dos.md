---
title: Denial of Service Vulnerability in Zebra
slug: 2026-10-zebra-dos
description: Zebra versions prior to 6.0.0 are vulnerable to an unauthenticated denial-of-service attack via the submission of non-standard high-sigop P2SH transactions that exhaust system resources.
date: "2026-10-02T14:24:50Z"
lastmod: "2026-10-02T14:24:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:zebra:zebra:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - blockchain
vendors:
  - Zebra
products:
  - Zebra (< 6.0.0)
  - Zebra (< 4.4.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Zebra before 6.0.0 contains a denial of service vulnerability that allows unauthenticated peers to stall Tokio workers.
    confidence_band: high
cves:
  - id: CVE-2026-104431
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104431
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104437
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Zebra to version 6.0.0 or later
      owner: IT Operations
      addresses: CVE-2026-104431
      evidence: Source states Zebra before 6.0.0 contains a denial of service vulnerability.
updates:
  - at: "2026-10-02T14:24:57Z"
    level: L1
    summary: added coverage for Zebra (< 4.4.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104437
---

Zebra versions prior to 6.0.0 contain a denial-of-service (DoS) vulnerability that allows unauthenticated network peers to compromise node stability. The vulnerability stems from the way the node handles mempool transactions; specifically, it allows the submission of non-standard transactions with high signature operation (sigop) counts. These transactions reach the CachedFfiTransaction::is_valid() verification function before standard validation checks are performed. By flooding the node with these computationally expensive transactions, an attacker can saturate the verifier buffer and stall the underlying Tokio workers. This resource exhaustion forces the node to become unresponsive, impacting the availability of the Zebra service. This vulnerability highlights the risk of processing complex transaction data before validating it against standard consensus rules.

## Impact

Successful exploitation results in a complete denial of service for the targeted Zebra node. By stalling the Tokio worker threads, the attacker renders the node unable to process legitimate blockchain data, participate in peer-to-peer communication, or perform synchronization tasks, effectively taking the node offline.

## Recommendation

Prioritized actions for administrators:

* Patch the affected Zebra software by upgrading to version 6.0.0 or later immediately to address CVE-2026-104431.
* Monitor network traffic and node logs for an unusual influx of high-sigop transactions or sudden spikes in resource utilization (CPU/Memory) corresponding to transaction validation.
* In resource-constrained or critical production environments, implement strict peer admission control or rate limiting for unauthenticated incoming connections to mitigate the impact of malicious transaction bursts until an upgrade is feasible.
