---
title: Denial of Service Vulnerability in BIND Named Service
slug: 2026-09-bind-dos
description: A memory management flaw in BIND 9 allows an attacker-controlled authoritative DNS server to trigger a service abort by providing a maliciously crafted 65536-byte negative DNS response.
date: "2026-09-16T15:50:09Z"
lastmod: "2026-09-17T13:13:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:isc:bind:9.11.0:*:*:*:*:*:*:*
  - cpe:2.3:a:isc:bind:9.18.50:*:*:*:*:*:*:*
  - cpe:2.3:a:isc:bind:9.20.27:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - dns
  - infrastructure
vendors:
  - Internet Systems Consortium
products:
  - BIND (9.11.0 - 9.18.50)
  - BIND (9.20.0 - 9.20.27)
  - BIND (9.21.0 - 9.21.25)
  - BIND Subscription Edition (9.11.3-S1 - 9.18.50-S1)
  - BIND Subscription Edition (9.20.9-S1 - 9.20.27-S1)
  - BIND (9.18.0 - 9.18.50)
  - BIND (9.18.11-S1 - 9.18.50-S1)
  - BIND (9.20.9-S1 - 9.20.27-S1)
  - BIND (9.20.0-9.20.27, 9.21.0-9.21.25, 9.20.9-S1-9.20.27-S1)
  - BIND (9.11.0 - 9.18.50, 9.20.0 - 9.20.27, 9.21.0 - 9.21.25, 9.11.3-S1 - 9.18.50-S1, 9.20.9-S1 - 9.20.27-S1)
  - BIND (9.20.0 <= version < 9.20.29, 9.21.0 <= version < 9.21.26)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Improper resource deallocation during the processing of these records can lead to memory exhaustion, preventing the resolver from performing recursive lookups and causing a denial-of-service condition.
    confidence_band: high
cves:
  - id: CVE-2026-19667
    cvss: 7.5
  - id: CVE-2026-76163
    cvss: 7.5
  - id: CVE-2026-19666
    cvss: 7.5
  - id: CVE-2026-81563
    cvss: 7.5
  - id: CVE-2026-77692
    cvss: 7.5
  - id: CVE-2026-81736
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19667
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81563
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76163
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80274
  - https://www.securityweek.com/isc-patches-14-vulnerabilities-in-bind-9-security-update/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade BIND to the latest patched version provided by Internet Systems Consortium
      owner: IT Operations
      addresses: CVE-2026-19667
      evidence: Source advisory confirms the vulnerability and mandates an update
updates:
  - at: "2026-09-16T15:50:26Z"
    level: L1
    summary: added coverage for BIND (9.18.0 - 9.18.50) +4 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-81563
  - at: "2026-09-16T17:51:54Z"
    level: L1
    summary: added coverage for BIND (9.20.0-9.20.27, 9.21.0-9.21.25, 9.20.9-S1-9.20.27-S1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76163
  - at: "2026-09-16T17:52:00Z"
    level: L1
    summary: added coverage for BIND (9.11.0 - 9.18.50, 9.20.0 - 9.20.27, 9.21.0 - 9.21.25, 9.11.3-S1 - 9.18.50-S1, 9.20.9-S1 - 9.20.27-S1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-80274
  - at: "2026-09-17T13:13:20Z"
    level: L2
    summary: added CVE-2026-19666 +4
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/isc-patches-14-vulnerabilities-in-bind-9-security-update/
---

Internet Systems Consortium (ISC) BIND 9 is susceptible to a denial-of-service (DoS) vulnerability, tracked as CVE-2026-19667. The vulnerability occurs when the `named` process receives a negative DNS response from an authoritative server that is precisely 65536 bytes in size. Under these specific conditions, the software creates a cache entry with a size of zero bytes. Subsequent attempts by the `named` service to read this invalid entry result in an assertion failure, forcing the process to abort. 

This issue affects a wide range of BIND versions, including the 9.11, 9.18, 9.20, and 9.21 branches, as well as their corresponding versions in the BIND Subscription Edition (S1). Given that `named` is a critical component of DNS infrastructure, a successful trigger of this abort will result in a complete loss of DNS resolution services for systems relying on the affected resolver, necessitating a manual restart of the service and leaving the organization vulnerable until the service is patched.

## Impact

The vulnerability results in a high-severity denial-of-service condition affecting the availability of DNS infrastructure. If successfully exploited, the `named` process crashes, leading to a complete outage of name resolution services for all clients served by the affected BIND instance. Organizations heavily dependent on internal BIND resolvers for network operations may experience widespread service disruption across their environment.

## Recommendation

1. Patch all vulnerable instances of BIND 9 immediately. Organizations should prioritize updating to the latest vendor-provided release that addresses CVE-2026-19667.
2. Implement monitoring to track `named` service crashes or restarts, which may indicate attempted exploitation or active service degradation.
3. Review DNS configurations to ensure that the resolver is not configured to trust unverified or suspicious authoritative servers that could be leveraged to deliver the malicious 65536-byte response.
4. Ensure all logging for the BIND service is centralized to capture error messages or assertions that occur immediately preceding a service crash.
