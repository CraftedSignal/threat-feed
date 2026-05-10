---
title: ldap3_proto LDAP Filter Stack Exhaustion Vulnerability
slug: 2026-05-ldap3-stack-exhaustion
description: The ldap3_proto package is vulnerable to LDAP Filter stack exhaustion due to unbounded query depth, potentially causing a denial of service in applications processing LDAP queries, affecting versions before 0.7.1.
date: "2026-05-06T23:39:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ldap
  - denial-of-service
  - rust
products:
  - ldap3_proto (< 0.7.1)
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-qcxq-75wr-5cm8
rules:
  - title: Detect Suspiciously Deep LDAP Queries
    description: Detects LDAP queries with excessive nesting depth, potentially indicating an exploitation attempt against ldap3_proto
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - network_connection
      - windows
  - title: Detect ldap3_proto Stack Exhaustion Crash
    description: Detects application crashes indicative of stack exhaustion when processing LDAP queries using vulnerable ldap3_proto libraries
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `ldap3_proto` package, a Rust library for implementing the LDAP protocol, is susceptible to a stack exhaustion vulnerability. This flaw arises because the library doesn't validate the depth of LDAP queries. An attacker can exploit this by sending a crafted LDAP query with excessive nesting, causing the parser (both PEG and ASN) to consume excessive stack space. This can lead to a denial-of-service (DoS) condition in applications that rely on `ldap3_proto` to process LDAP queries. The vulnerability affects versions of `ldap3_proto` prior to 0.7.1. This poses a risk to applications using the vulnerable library, potentially disrupting services.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of `ldap3_proto` (< 0.7.1).
2. The attacker crafts a malicious LDAP query with deeply nested filters. The LDAP query exploits the lack of depth validation in the ldap3_proto library.
3. The attacker sends the crafted LDAP query to the target application. The query is sent over a network connection to the LDAP service.
4. The application receives the LDAP query and passes it to the `ldap3_proto` library for parsing. The application uses the vulnerable library to parse the received LDAP query.
5. The `ldap3_proto` library attempts to parse the deeply nested LDAP filter. The parser exhausts the stack space.
6. Stack exhaustion occurs, leading to a denial-of-service condition. The vulnerable application crashes or becomes unresponsive due to stack exhaustion.
7. Legitimate users are unable to access the affected service or application. Users experience service disruptions or application unavailability.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, rendering applications using the `ldap3_proto` library unavailable. The impact is limited to availability, as the vulnerability does not directly compromise confidentiality or integrity. The number of affected applications depends on the adoption of the vulnerable `ldap3_proto` library. Organizations using applications with this vulnerability may experience service disruptions and potential data loss due to application crashes.

## Recommendation

*   Upgrade the `ldap3_proto` package to version 0.7.1 or later to remediate the vulnerability.
*   Deploy the Sigma rule "Detect Suspiciously Deep LDAP Queries" to identify potential exploitation attempts by monitoring network traffic for unusually large LDAP queries.
