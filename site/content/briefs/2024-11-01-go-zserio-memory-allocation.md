---
title: go-zserio Unbounded Memory Allocation Vulnerability
slug: 2024-11-01-go-zserio-memory-allocation
description: go-zserio versions prior to 0.9.1 are vulnerable to unbounded memory allocation when deserializing data, potentially leading to denial of service.
date: "2024-11-01T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - memory-allocation
  - denial-of-service
  - go-zserio
vendors:
  - Toyota
products:
  - go-zserio
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1499
    technique_name: Resource Exhaustion
references:
  - https://github.com/advisories/GHSA-xhj4-g6w8-2xjw
  - https://github.com/woven-by-toyota/go-zserio/commit/39ef1decde7e9766207794d396018776b33c6e45
rules:
  - title: Detect Suspicious Large Memory Allocation
    description: Detects processes that allocate an unusually large amount of memory, potentially indicating exploitation of memory allocation vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Large Memory Allocation (Linux)
    description: Detects processes that allocate an unusually large amount of memory on Linux, potentially indicating exploitation of memory allocation vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability exists in the go-zserio library, a tool used for serializing data structures, specifically in versions prior to 0.9.1. The vulnerability stems from how the library handles deserialization of arrays, strings, and byte arrays (blobs). When processing these data types, go-zserio reads a size value directly from the input data stream and uses this value to allocate memory. Because the library trusts the provided size without proper validation, a malicious actor can craft a data file containing an extremely large size value. This causes the go-zserio runtime to allocate an excessive amount of memory, potentially exhausting system resources and resulting in a denial-of-service (DoS) condition. The vulnerable library could be integrated into any application that parses untrusted data using go-zserio.

## Attack Chain

1.  Attacker crafts a malicious zserio data file containing an excessively large size value for an array, string, or blob field.
2.  The attacker delivers the malicious data file to a vulnerable application that uses go-zserio for data deserialization. This could be achieved through various means, such as uploading the file to a server, sending it as an attachment, or including it in a network packet.
3.  The vulnerable application receives the malicious data file and attempts to deserialize it using the go-zserio library.
4.  The go-zserio library reads the large size value from the malicious data file.
5.  Based on this untrusted size value, the go-zserio library attempts to allocate a large amount of memory to store the incoming data.
6.  The memory allocation request consumes significant system resources, potentially exhausting available memory.
7.  The system may become unresponsive or crash due to memory exhaustion.
8.  The application experiences a denial-of-service condition, becoming unavailable to legitimate users.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition. The affected application becomes unavailable, impacting business operations and potentially causing data loss or corruption. The severity of the impact depends on the role and importance of the application within the organization's infrastructure. It is not known how many organizations are affected by this vulnerability.

## Recommendation

*   Upgrade to go-zserio version 0.9.1 or later to patch the vulnerability.
*   Implement input validation to check the size of arrays, strings, and blobs before deserialization, preventing excessive memory allocation.
*   Deploy the Sigma rule `Detect Suspicious Large Memory Allocation` to identify processes allocating unusually large amounts of memory, which may indicate exploitation attempts.
*   Monitor applications that use go-zserio for excessive memory consumption using system monitoring tools.
