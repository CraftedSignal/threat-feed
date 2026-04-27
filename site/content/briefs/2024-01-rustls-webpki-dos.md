---
title: rustls-webpki Denial-of-Service Vulnerability via Malformed CRL BIT STRING
slug: 2024-01-rustls-webpki-dos
description: A denial-of-service vulnerability exists in rustls-webpki versions prior to 0.103.13 and between 0.104.0-alpha.1 and 0.104.0-alpha.7 due to a panic in `bit_string_flags()` when processing a malformed CRL BIT STRING, triggered when CRL checking is enabled and an attacker provides a crafted CRL.
date: "2024-01-09T12:00:00Z"
severities:
  - medium
tags:
  - denial-of-service
  - rustls-webpki
  - crl
vendors:
  - rust
products:
  - rustls-webpki
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-82j2-j2ch-gfr8
rules:
  - title: Detect Malformed CRL Bit String
    description: Detects malformed CRLs with a BIT STRING containing only 0x00 in the issuingDistributionPoint extension, which triggers a panic in rustls-webpki.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - windows
  - title: Detect Panic in rustls-webpki via Sysmon
    description: Detects process termination events indicative of a panic in rustls-webpki due to the malformed CRL processing vulnerability.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A denial-of-service vulnerability has been identified in the rustls-webpki crate, specifically affecting versions prior to 0.103.13 and versions between 0.104.0-alpha.1 and 0.104.0-alpha.7. The vulnerability stems from a panic within the `bit_string_flags()` function located in `src/der.rs`. This panic occurs when the function processes a malformed Certificate Revocation List (CRL) containing a BIT STRING with a content of exactly `[0x00]`. The issue is triggered via the…
