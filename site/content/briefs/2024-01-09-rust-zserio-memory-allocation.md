---
title: rust-zserio Unbounded Memory Allocation Vulnerability
slug: 2024-01-09-rust-zserio-memory-allocation
description: The rust-zserio package is vulnerable to unbounded memory allocation when deserializing arrays, strings, or bytes (blob) types, allowing an attacker to cause a denial-of-service by providing a crafted data file with a large size value.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - memory-allocation
vendors:
  - rust
products:
  - rust-zserio (<= 0.5.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-fpf5-4jw8-67x8
rules:
  - title: Detect Excessive Memory Allocation by rust-zserio
    description: Detects processes that may be exploiting the rust-zserio unbounded memory allocation vulnerability by monitoring for excessive memory usage.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    data_sources:
      - process_creation
      - linux
  - title: Detect Suspicious File Reads Associated with rust-zserio
    description: Detects attempts to read files with large size values, potentially indicating exploitation of the rust-zserio vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The rust-zserio package, versions 0.5.3 and earlier, is susceptible to an unbounded memory allocation vulnerability. This flaw arises during the deserialization of arrays, strings, or byte (blob) types. The library reads the size of the incoming data from the serialized input itself, and subsequently allocates memory based on this size. Due to the absence of proper size validation, a malicious actor can exploit this by crafting a data file containing an excessively large size value. This would force the rust-zserio runtime to allocate a substantial amount of memory, potentially leading to a denial-of-service condition. This vulnerability poses a significant risk to applications that process zserio-encoded messages from untrusted sources, as it can be triggered remotely through a specially crafted input.

## Attack Chain

1. An attacker crafts a malicious zserio-encoded data file.
2. The malicious data file contains a manipulated size value for an array, string, or blob field. This size value is set to an extremely large number.
3. The vulnerable rust-zserio library attempts to deserialize the data file.
4. During deserialization, the library reads the manipulated size value from the data file.
5. The library attempts to allocate memory based on the excessively large size value.
6. The excessive memory allocation consumes available system resources.
7. The application becomes unresponsive due to resource exhaustion.
8. The system experiences a denial-of-service, impacting availability.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition. Affected applications become unresponsive, potentially disrupting critical services. The number of victims depends on the prevalence of rust-zserio in systems that process untrusted data. The impact is significant, as it can lead to service outages and potentially impact other applications running on the same system due to resource exhaustion.

## Recommendation

*   Apply the patch from commit [57f5fb](https://github.com/Danaozhong/rust-zserio/commit/57f5fb4a2a8611d58dbcc1a9221349206dd99c3c) to remediate the unbounded memory allocation vulnerability.
*   Implement input validation to check the size of arrays, strings, or blob types before memory allocation.
*   Monitor resource consumption of rust-zserio applications to detect abnormal memory allocation patterns. Deploy the "Detect Excessive Memory Allocation by rust-zserio" Sigma rule to identify potential exploitation attempts.
