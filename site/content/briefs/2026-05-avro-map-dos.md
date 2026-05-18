---
title: Avro Map Decoder Vulnerable to Denial-of-Service via Unbounded Memory Allocation
slug: 2026-05-avro-map-dos
description: The Avro map decoder accepted attacker-controlled block-element counts, leading to unbounded map growth and potential denial-of-service via memory exhaustion; upgrading to v2.33.0 requires explicit configuration of MaxMapAllocSize to mitigate the vulnerability.
date: "2026-05-18T13:02:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - memory-exhaustion
  - avro
  - data-serialization
vendors:
  - Iskorotkov
  - Hamba
products:
  - avro
  - avro/v2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-mx64-mj3q-7prj
  - https://github.com/iskorotkov/avro/pull/5
  - https://github.com/iskorotkov/avro/commit/5192df96a158999344ac96ebcb1f7461d626f6d7
  - https://github.com/iskorotkov/avro/commit/534c7518152a893d8b4dea962669bd1123308a00
  - https://github.com/iskorotkov/avro/releases/tag/v2.33.0
  - https://github.com/iskorotkov/avro/blob/main/SECURITY.md
  - https://github.com/iskorotkov/avro/security/advisories/GHSA-mc57-h6j3-3hmv
  - https://github.com/iskorotkov/avro/security/advisories/GHSA-w8j3-pq8g-8m7w
  - https://pkg.go.dev/vuln/GO-2023-1930
  - https://github.com/hamba/avro
rules:
  - title: Detect Avro Decoder Unbounded Map Allocation Attempt
    description: Detects processes attempting to decode Avro data with unusually large map allocation sizes, potentially indicative of a denial-of-service attack. Tuning might be required.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Avro Decoder Unbounded Map Allocation Error
    description: Detects a specific error message indicating that map allocation limits have been exceeded during Avro decoding, signaling a potential DoS attack.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - application
      - linux
rules_count: 2
---

The Avro map decoder in `iskorotkov/avro/v2` prior to version 2.33.0 is vulnerable to a denial-of-service attack due to unbounded memory allocation. The decoder processes attacker-controlled block-element counts from the wire format without enforcing an upper bound on the map size. This allows a malicious producer to declare an arbitrarily large map, either in a single block or chunked across multiple blocks, leading to excessive memory consumption and potentially crashing the application due to out-of-memory errors. The vulnerability exists because the map decoder lacked the `Config.MaxMapAllocSize` limit that was present in the slice decoder to prevent similar attacks against arrays. To mitigate this, version 2.33.0 introduces `Config.MaxMapAllocSize`, but it's opt-in, requiring explicit configuration to activate the limit.

## Attack Chain

1.  Attacker crafts a malicious Avro payload with an extremely large map size declaration.
2.  The payload is sent to a vulnerable Avro decoder instance.
3.  The decoder reads the initial block header, which specifies a large element count.
4.  Without `MaxMapAllocSize` configured, the decoder attempts to allocate memory for the map based on the attacker-controlled size.
5.  If the initial block isn't large enough to exhaust memory, the attacker splits the large map into smaller blocks, each declaring element counts below a per-block threshold.
6.  The decoder reads subsequent block headers and continues allocating memory, growing the map incrementally.
7.  The cumulative memory allocation exceeds available resources.
8.  The application crashes due to an out-of-memory (OOM) error, resulting in a denial-of-service.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition. The affected service becomes unavailable, impacting all users. The severity depends on the resources allocated to the affected service and the size of the map specified in the malicious payload. If not properly configured, applications using affected versions of the Avro decoder are susceptible to memory exhaustion, potentially leading to service outages.

## Recommendation

*   Upgrade to `github.com/iskorotkov/avro/v2` version 2.33.0 or later and explicitly set a non-zero value for `Config.MaxMapAllocSize` based on your schema's requirements as described in the mitigation section.
*   If using `github.com/hamba/avro/v2`, migrate to `github.com/iskorotkov/avro/v2 >= v2.33.0` and configure `MaxMapAllocSize` due to the archived nature of the original module.
*   Deploy the Sigma rule "Detect Avro Decoder Unbounded Map Allocation Attempt" to monitor for unusually large map allocation attempts in Avro decoding processes.
*   Implement resource constraints, such as memory limits within child processes or cgroups, to contain potential OOM errors if immediate upgrades are not feasible.
*   Reject inputs from untrusted sources lacking resource controls to prevent potential exploitation attempts.
