---
title: Resource Exhaustion Vulnerability in BIND 9 DNSSEC Validation (CVE-2026-11605)
slug: 2026-07-bind9-resource-exhaustion
description: A resource exhaustion vulnerability, CVE-2026-11605, affects specific versions of ISC BIND 9, where DNSSEC validation disproportionately consumes CPU resources when processing superfluous RRSIG records, potentially leading to a denial of service.
date: "2026-07-22T15:19:51Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - dns
  - dnssec
  - vulnerability
  - denial-of-service
  - resource-exhaustion
vendors:
  - Internet Systems Consortium (ISC)
products:
  - BIND 9 (9.20.0 through 9.20.24)
  - BIND 9 (9.21.0 through 9.21.23)
  - BIND 9 (9.20.9-S1 through 9.20.24-S1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A query to an authoritative server/zone which returns many valid but superfluous RRSIG records causes the validator to waste disproportionate CPU time.
    confidence_band: high
cves:
  - id: CVE-2026-11605
    cvss: 7.5
references:
  - https://downloads.isc.org/isc/bind9/9.20.26
  - https://downloads.isc.org/isc/bind9/9.21.24
  - https://kb.isc.org/docs/cve-2026-11605
---

A high-severity resource exhaustion vulnerability, identified as CVE-2026-11605, has been discovered in multiple versions of ISC BIND 9. This flaw stems from BIND's DNSSEC validation process, which validates all RRSIG (DNSSEC Signature) records in a DNS answer, even if they are not strictly necessary for the query's resolution. An attacker can exploit this by sending a crafted DNS response containing numerous valid but superfluous RRSIG records from an authoritative server they control. When a vulnerable BIND resolver processes such a response, it wastes disproportionate CPU time on unnecessary validation, leading to resource exhaustion and potential denial of service for critical DNS resolution services. This issue affects BIND 9 versions 9.20.0 through 9.20.24, 9.21.0 through 9.21.23, and 9.20.9-S1 through 9.20.24-S1.

## Attack Chain

1. An attacker identifies a vulnerable BIND 9 recursive resolver.
2. The attacker operates or compromises an authoritative DNS server for a domain.
3. The attacker crafts DNSSEC records to include an excessive number of valid but superfluous RRSIG records for the controlled domain.
4. The vulnerable BIND 9 resolver makes a DNS query that necessitates resolution via the attacker's authoritative server.
5. The attacker's authoritative server responds to the BIND 9 resolver with the crafted DNSSEC response containing numerous RRSIG records.
6. The vulnerable BIND 9 resolver attempts to validate all received RRSIG records, regardless of their necessity.
7. This excessive validation process consumes a disproportionate amount of CPU time on the BIND 9 resolver.
8. The BIND 9 resolver experiences resource exhaustion, leading to a denial of service condition for DNS resolution services.

## Impact

Successful exploitation of CVE-2026-11605 results in a denial of service (DoS) for the affected BIND 9 DNS resolver. This can significantly disrupt network operations by preventing users and systems from resolving domain names, thereby impacting access to websites, applications, and other network services. The impact is primarily on the availability of DNS services, leading to widespread outages for any clients relying on the compromised resolver. The vulnerability has a CVSS v3.1 Base Score of 7.5 (High), reflecting its significant impact on availability without requiring authentication or user interaction.

## Recommendation

* Patch CVE-2026-11605 immediately by upgrading affected BIND 9 instances to versions 9.20.25, 9.21.24, or later. Refer to the ISC download links in the references.
* Monitor the CPU utilization of BIND 9 servers for unusual spikes, which could indicate an attempted or successful resource exhaustion attack due to CVE-2026-11605.
* Review DNS traffic patterns for unusually large DNSSEC responses, specifically those containing an excessive number of RRSIG records, which could be an indicator of an attack targeting CVE-2026-11605.
