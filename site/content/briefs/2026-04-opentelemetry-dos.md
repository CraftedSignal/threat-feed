---
title: OpenTelemetry-Go Multi-Value Baggage Header DOS Vulnerability
slug: 2026-04-opentelemetry-dos
description: A vulnerability in OpenTelemetry-Go allows attackers to amplify CPU and allocation usage by sending many `baggage:` header lines, leading to a denial-of-service condition due to excessive resource consumption.
date: "2026-04-08T12:00:00Z"
severities:
  - high
tags:
  - dos
  - opentelemetry
  - header injection
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Standard Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: 'Endpoint Denial of Service: Application Exhaustion'
references:
  - https://github.com/advisories/GHSA-mh2q-q3fh-2475
  - https://github.com/open-telemetry/opentelemetry-go/blob/1ee4a4126dbdd1bc79e9fae072fa488beffac52a/propagation/baggage.go#L58
rules:
  - title: Detect High Baggage Header Count
    description: Detects HTTP requests with a large number of baggage headers, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Large Allocations from Baggage Parsing
    description: Detects processes that may be allocating excessive memory due to baggage parsing in OpenTelemetry.
    platform: sigma
    severity: low
    tactics:
      - denial_of_service
      - resource_hijacking
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A remote denial-of-service vulnerability exists in OpenTelemetry-Go versions 1.36.0 through 1.40.0. The vulnerability stems from the `extractMultiBaggage` function parsing each `baggage:` header field-value independently and aggregating members across values. This allows an attacker to bypass the intended 8192-byte per-value parse limit by sending numerous `baggage:` header lines. Even when individual header values are within the limit, the aggregate parsing overhead can exhaust server…
