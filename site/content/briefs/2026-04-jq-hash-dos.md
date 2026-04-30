---
title: jq JSON Processor Hash Table Collision Denial-of-Service Vulnerability (CVE-2026-40164)
slug: 2026-04-jq-hash-dos
description: A denial-of-service vulnerability exists in jq versions prior to commit 0c7d133c3c7e37c00b6d46b658a02244fdd3c784 due to the use of a hardcoded seed in MurmurHash3, enabling attackers to craft JSON objects that trigger hash collisions and cause excessive CPU consumption.
date: "2026-04-14T00:16:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - jq
  - denial-of-service
  - hash-collision
  - CVE-2026-40164
  - linux
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-40164
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40164
rules:
  - title: Detect High CPU Usage by jq
    description: Detects when the jq process is consuming a high percentage of CPU, which may indicate a DoS attack via hash collision.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect jq Process Arguments with Large Input
    description: Detects jq process invocations with unusually large command line arguments, which can be indicative of crafted JSON input causing hash collisions.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-40164 identifies a denial-of-service (DoS) vulnerability affecting the `jq` command-line JSON processor. Prior to commit 0c7d133c3c7e37c00b6d46b658a02244fdd3c784, `jq` employed MurmurHash3 with a fixed, publicly known seed (0x432A9843) for all JSON object hash table operations. This weakness allowed a malicious actor to precompute key collisions offline. An attacker could then supply a specially crafted JSON object, roughly 100KB in size, where all keys hash to the same bucket. This forces hash table lookups to degrade from O(1) to O(n) complexity, effectively turning any `jq` expression into an O(n²) operation, resulting in significant CPU exhaustion. The vulnerability impacts common `jq` use cases, including CI/CD pipelines, web services, and data processing scripts. The vulnerability has been addressed in commit 0c7d133c3c7e37c00b6d46b658a02244fdd3c784.

## Attack Chain

1. The attacker analyzes the `jq` source code and identifies the use of MurmurHash3 with the hardcoded seed 0x432A9843.
2. The attacker develops a script to generate JSON keys that will collide with each other when hashed using MurmurHash3 and the specific seed.
3. The attacker crafts a JSON object, approximately 100KB in size, containing numerous colliding keys.
4. The attacker submits this malicious JSON object to a system running `jq`, potentially via an API endpoint or as input to a data processing script.
5. The `jq` process parses the JSON object and attempts to perform hash table lookups. Due to the collisions, these lookups become extremely slow, consuming excessive CPU resources.
6. The CPU utilization on the target system spikes, potentially impacting the performance of other applications.
7. The `jq` process may become unresponsive or crash due to resource exhaustion.
8. The system experiences a denial-of-service condition, preventing legitimate users or processes from accessing `jq` functionality.

## Impact

Successful exploitation of CVE-2026-40164 can lead to denial-of-service conditions on systems utilizing the `jq` JSON processor. The vulnerability impacts environments where `jq` is used, including CI/CD pipelines, web services, and data processing scripts. If successfully exploited, critical processes relying on `jq` may become unavailable, leading to disruptions in automated workflows, web application outages, and data processing delays. The relatively small size of the malicious JSON payload (approximately 100KB) makes this vulnerability practical and easily exploitable.

## Recommendation

*   Upgrade to `jq` version containing commit 0c7d133c3c7e37c00b6d46b658a02244fdd3c784 or later to patch the vulnerability (reference: CVE-2026-40164).
*   Monitor CPU utilization on systems running `jq` for unusually high activity, especially when processing JSON data, to detect potential exploitation attempts (reference: Attack Chain - Step 6).
*   Implement resource limits and rate limiting on services that accept JSON input to mitigate the impact of denial-of-service attacks (reference: Impact).
