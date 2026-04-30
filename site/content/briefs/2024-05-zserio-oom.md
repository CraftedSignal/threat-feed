---
title: Zserio Runtime Unbounded Memory Allocation Vulnerability
slug: 2024-05-zserio-oom
description: A crafted payload can force memory allocations of up to 16 GB, leading to a denial-of-service condition in applications using the Zserio serialization framework, including those within the automotive Navigation Data Standard (NDS).
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - zserio
  - denial-of-service
  - memory-allocation
  - nds
vendors:
  - Toyota
  - BMW
  - Volkswagen
  - Mercedes-Benz
products:
  - Navigation Data Standard (NDS)
  - zserio-runtime
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-cwq5-8pvq-j65j
  - https://github.com/ndsev/zserio/releases/tag/v2.18.1
rules:
  - title: Detect Zserio Large Memory Allocation
    description: Detects processes attempting to allocate extremely large memory regions, potentially indicating exploitation of the Zserio unbounded memory allocation vulnerability. Tune the threshold for your environment.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Java Zserio Large Memory Allocation
    description: Detects Java processes attempting to allocate extremely large arrays, potentially indicating exploitation of the Zserio unbounded memory allocation vulnerability in Java environments. Tune the threshold for your environment.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A critical vulnerability exists within the Zserio runtime library, a serialization framework used in various applications, including the Navigation Data Standard (NDS) for automotive systems. This flaw allows a malicious actor to trigger an unbounded memory allocation by providing a specially crafted input. A payload as small as 4-5 bytes can cause memory allocations of up to 16 GB, resulting in a denial-of-service (DoS) condition due to an out-of-memory (OOM) error. This issue affects Zserio versions 2.18.0 and earlier. The vulnerability stems from insufficient validation of the declared size of data structures during deserialization, leading to excessive memory reservation. Exploitation could disrupt critical systems relying on Zserio, particularly within the automotive sector where NDS is widely deployed.

## Attack Chain

1. An attacker crafts a malicious NDS data payload.
2. The payload includes a "varsize" field claiming an extremely large size (e.g., 2,147,483,647 bytes).
3. The vulnerable Zserio runtime attempts to deserialize the payload.
4. The `Array.h` or `Array.java` code calls `reserve()` or `reset()` with the attacker-controlled size.
5. The system attempts to allocate a large block of memory (up to 16 GB), based on the attacker-specified size.
6. Memory allocation fails, or consumes excessive resources.
7. The application crashes due to an out-of-memory (OOM) error.
8. The denial-of-service condition prevents the application from functioning correctly.

## Impact

The vulnerability affects applications utilizing the Zserio serialization framework, including the Navigation Data Standard (NDS) used by 43 member companies, including Toyota, BMW, Volkswagen, and Mercedes-Benz. Successful exploitation can lead to a denial-of-service (DoS) condition, potentially impacting millions of cars on the road that rely on NDS for map updates and navigation data. Attack vectors include NDS.Live cloud map updates, map data supply chain compromise, and backend data processing pipelines. On 32-bit automotive ECUs, this could affect ADAS functionality. A 4-byte payload can trigger the allocation of 762MB of memory, and a 5-byte payload triggers an allocation of 16GB, leading to a system crash.

## Recommendation

*   Apply the patch available in Zserio version 2.18.1 to remediate the vulnerability ([https://github.com/ndsev/zserio/releases/tag/v2.18.1](https://github.com/ndsev/zserio/releases/tag/v2.18.1)).
*   Implement input validation to ensure that the declared size of data structures during deserialization does not exceed the remaining size of the input stream, as suggested in the advisory.
*   Deploy the Sigma rule `Detect Zserio Large Memory Allocation` to identify potential exploitation attempts in environments where Zserio is used.
