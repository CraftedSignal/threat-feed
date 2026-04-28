---
title: NestJS Microservices Denial-of-Service via Recursive handleData
slug: 2026-04-nestjs-dos
description: A denial-of-service vulnerability exists in NestJS's @nestjs/microservices package, affecting versions 11.1.18 and earlier, where an attacker can send multiple small, valid JSON messages within a single TCP frame, causing a stack overflow.
date: "2026-04-14T00:15:09Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - nestjs
  - denial-of-service
  - microservices
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-hpwf-8g29-85qm
rules:
  - title: Detect Excessive TCP Data
    description: Detects unusually large TCP packets, which could indicate a denial-of-service attack targeting a NestJS microservice.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - linux
  - title: Detect NestJS Microservice Process Crashes
    description: Detects crashes of NestJS microservice processes, potentially indicating a denial-of-service due to the recursive handleData vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A denial-of-service vulnerability has been identified in the `@nestjs/microservices` package, specifically impacting versions up to and including 11.1.18. This vulnerability arises from the recursive nature of the `handleData()` function when processing JSON messages over TCP. An attacker can exploit this by sending a single TCP frame containing numerous small, valid JSON messages. This triggers excessive recursion, rapidly consuming stack space and ultimately leading to a stack overflow. A relatively small payload of approximately 47 KB is sufficient to trigger the `RangeError` and cause the application to crash, effectively denying service to legitimate users. The vulnerability was discovered by https://github.com/hwpark6804-gif and has been addressed in version 11.1.19 of the `@nestjs/microservices` package.

## Attack Chain

1.  The attacker establishes a TCP connection to the NestJS microservice endpoint.
2.  The attacker crafts a TCP frame containing multiple small, valid JSON messages.
3.  The attacker sends the crafted TCP frame to the microservice.
4.  The `handleData()` function in `@nestjs/microservices` receives the TCP frame.
5.  For each JSON message in the frame, `handleData()` recursively calls itself.
6.  With each recursive call, the buffer size shrinks, preventing the `maxBufferSize` from being reached.
7.  The call stack overflows due to the excessive recursion.
8.  A `RangeError` is triggered, crashing the NestJS microservice and causing a denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, rendering the affected NestJS microservice unavailable. This can disrupt critical application functionality that relies on the microservice. While the specific number of victims or sectors targeted is unknown, any application using a vulnerable version of `@nestjs/microservices` is susceptible. A successful attack leads to application downtime and potential data loss or corruption if the microservice is responsible for data persistence.

## Recommendation

*   Upgrade the `@nestjs/microservices` package to version 11.1.19 or later to remediate the vulnerability (reference: `@nestjs/microservices@11.1.19`).
*   Deploy the Sigma rule "Detect Excessive TCP Data" to identify potential exploitation attempts by monitoring for unusually large TCP packets (reference: rule "Detect Excessive TCP Data").
*   Monitor network traffic for connections sending abnormally large amounts of data to NestJS microservice endpoints.
