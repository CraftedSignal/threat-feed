---
title: graphql-php OverlappingFieldsCanBeMerged Quadratic Complexity Vulnerability
slug: 2026-05-graphql-php-resource-exhaustion
description: The `OverlappingFieldsCanBeMerged` validation rule in `webonyx/graphql-php` has an `O(n^2 x m^2)` worst-case complexity due to flattened inline fragments, leading to potential resource exhaustion.
date: "2026-05-05T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - graphql
  - php
  - resource-exhaustion
  - vulnerability
vendors:
  - webonyx
products:
  - graphql-php
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Resource Hijacking
cves:
  - id: CVE-2023-26144
    cvss: 5.3
    epss: 0.0214
references:
  - https://github.com/advisories/GHSA-fc86-6rv6-2jpm
  - https://github.com/advisories/GHSA-9pv7-vfvm-6vr7
  - https://github.com/advisories/GHSA-p4qx-6w5p-4rj2
  - https://github.com/graphql/graphql-js/issues/2185
  - https://github.com/sangria-graphql-org/sangria/pull/12
rules:
  - title: Detect GraphQL PHP Excessive Validation Time
    description: Detects excessive validation time in PHP processes, which may indicate a GraphQL resource exhaustion attack.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
  - title: Detect GraphQL PHP Spawning Many Processes
    description: Detects a high number of PHP processes being spawned, which may indicate a GraphQL resource exhaustion attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The `OverlappingFieldsCanBeMerged` validation rule in `webonyx/graphql-php` is vulnerable to a quadratic complexity issue due to how it handles inline fragments. Specifically, the pairwise comparison loop within the `collectConflictsWithin` function can lead to an `O(n^2 x m^2)` worst-case scenario when processing queries with nested inline fragments. A 364 KB query with 200 outer and 100 inner inline fragments was observed to consume 117 seconds of CPU time per request on `webonyx/graphql-php@v15.31.4` running on PHP 8.3.30. The existing named-fragment cache (CVE-2023-26144) does not cover inline fragments, making the system vulnerable to denial-of-service attacks through resource exhaustion. This affects applications using the standard validation pipeline, including Lighthouse, Overblog/GraphQLBundle, wp-graphql, and Drupal GraphQL.

## Attack Chain

1. An attacker crafts a GraphQL query with a large number of nested inline fragments.
2. The query is submitted to a `webonyx/graphql-php` application.
3. The `DocumentValidator::validate()` function invokes the default rules, including `OverlappingFieldsCanBeMerged`.
4. Within `OverlappingFieldsCanBeMerged.php`, the `internalCollectFieldsAndFragmentNames` function flattens inline fragments into the parent `$astAndDefs` map, increasing the size of the map.
5. The `collectConflictsWithin` function iterates through the flattened fields, performing an `O(n^2)` pairwise comparison of fields.
6. The `findConflict` function is recursively called for sub-selections, compounding the cost to `O(n^2 x m^2)`.
7. Due to the absence of a comparison budget or validation timeout, the validation process consumes excessive CPU resources.
8. The PHP worker process becomes pinned, leading to potential denial of service via worker pool exhaustion.

## Impact

A successful attack can lead to a denial of service (DoS) due to the exhaustion of server resources. A single 364 KB query can consume 117 seconds of CPU time, potentially exhausting the php-fpm worker pool. Systems with default configurations, such as Lighthouse/Laravel deployments, may be vulnerable even with `max_execution_time` limits, as the worker may burn significant CPU time before being terminated. Exploitation can bypass body-size limits and WAF rules via gzip compression, as the decompressed payload is much larger than the compressed one. The vulnerability affects all applications using the standard validation pipeline in `webonyx/graphql-php` versions prior to 15.32.2.

## Recommendation

*   Upgrade to `webonyx/graphql-php` version 15.32.2 or later, which includes a fix that addresses this vulnerability.
*   Implement a comparison budget in `OverlappingFieldsCanBeMerged` to limit the number of comparisons performed during validation, as described in the remediation options.
*   Consider capping inline-fragment flattening in `internalCollectFieldsAndFragmentNames` to prevent excessive growth of the `$astAndDefs` map, as outlined in the remediation options.
*   Deploy the Sigma rule `Detect GraphQL PHP Excessive Validation Time` to identify potential exploitation attempts by monitoring the execution time of GraphQL validation processes.
