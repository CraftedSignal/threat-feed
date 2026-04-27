---
title: Zserio Runtime Unbounded Memory Allocation Vulnerability
slug: 2024-05-zserio-oom
description: A crafted payload can force memory allocations of up to 16 GB, leading to a denial-of-service condition in applications using the Zserio serialization framework, including those within the automotive Navigation Data Standard (NDS).
date: "2024-05-02T12:00:00Z"
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

A critical vulnerability exists within the Zserio runtime library, a serialization framework used in various applications, including the Navigation Data Standard (NDS) for automotive systems. This flaw allows a malicious actor to trigger an unbounded memory allocation by providing a specially crafted input. A payload as small as 4-5 bytes can cause memory allocations of up to 16 GB, resulting in a denial-of-service (DoS) condition due to an out-of-memory (OOM) error. This issue affects Zserio…
