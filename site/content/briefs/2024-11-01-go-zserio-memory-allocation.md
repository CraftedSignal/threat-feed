---
title: go-zserio Unbounded Memory Allocation Vulnerability
slug: 2024-11-01-go-zserio-memory-allocation
description: go-zserio versions prior to 0.9.1 are vulnerable to unbounded memory allocation when deserializing data, potentially leading to denial of service.
date: "2024-11-01T12:00:00Z"
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

A critical vulnerability exists in the go-zserio library, a tool used for serializing data structures, specifically in versions prior to 0.9.1. The vulnerability stems from how the library handles deserialization of arrays, strings, and byte arrays (blobs). When processing these data types, go-zserio reads a size value directly from the input data stream and uses this value to allocate memory. Because the library trusts the provided size without proper validation, a malicious actor can craft a…
