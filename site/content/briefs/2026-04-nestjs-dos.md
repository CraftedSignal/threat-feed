---
title: NestJS Microservices Denial-of-Service via Recursive handleData
slug: 2026-04-nestjs-dos
description: A denial-of-service vulnerability exists in NestJS's @nestjs/microservices package, affecting versions 11.1.18 and earlier, where an attacker can send multiple small, valid JSON messages within a single TCP frame, causing a stack overflow.
date: "2026-04-14T00:15:09Z"
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

A denial-of-service vulnerability has been identified in the `@nestjs/microservices` package, specifically impacting versions up to and including 11.1.18. This vulnerability arises from the recursive nature of the `handleData()` function when processing JSON messages over TCP. An attacker can exploit this by sending a single TCP frame containing numerous small, valid JSON messages. This triggers excessive recursion, rapidly consuming stack space and ultimately leading to a stack overflow. A…
