---
title: pyasn1 Uncontrolled Resource Consumption (CVE-2026-59886)
slug: 2026-07-pyasn1-uncontrolled-resource-consumption
description: The pyasn1 library is vulnerable to uncontrolled resource consumption (excessive CPU and memory) when converting BER/CER/DER-encoded REAL values to Python floats, which can lead to a denial of service (DoS) in applications that decode untrusted ASN.1 data and then perform operations like printing, logging, comparing, or arithmetic on the decoded `univ.Real` objects.
date: "2026-07-21T19:15:06Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:pyasn1:pyasn1:*:*:*:*:*:python:*:*
tags:
  - denial-of-service
  - vulnerability
  - python
  - library
vendors:
  - pyasn1
products:
  - pyasn1 <= 0.6.3
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Applications that decode untrusted ASN.1 data and then print, log, or compare the decoded objects are vulnerable to denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-59886
    cvss: 7.5
    epss: 0.00339
references:
  - https://github.com/advisories/GHSA-hm4w-wwcw-mr6r
  - CVE-2026-59886
---

A critical vulnerability (CVE-2026-59886) has been identified in the `pyasn1` Python library, specifically affecting versions up to 0.6.3. This flaw, classified as uncontrolled resource consumption, arises when the `univ.Real` type converts specially crafted BER/CER/DER-encoded ASN.1 REAL values to Python floats. An attacker can craft a REAL value with a large exponent, which, upon conversion (e.g., via printing, logging, comparison, or arithmetic operations), attempts to materialize an astronomically large integer. This computationally intensive process consumes excessive CPU and memory, leading to a denial of service in applications that decode untrusted ASN.1 data and subsequently operate on these decoded objects. The issue is purely a DoS vector and does not involve remote code execution or data exfiltration. The vulnerability is fixed in `pyasn1` version 0.6.4, released to address this resource exhaustion attack.

## Attack Chain

1. An attacker crafts a malicious BER/CER/DER-encoded ASN.1 REAL value containing a very large exponent.
2. A vulnerable application, using `pyasn1` versions <= 0.6.3, receives and decodes untrusted ASN.1 data.
3. The `pyasn1.codec.ber`, `cer`, or `der` decoders process the input, creating a `pyasn1.type.univ.Real` object.
4. The application then performs an operation that implicitly or explicitly triggers a float conversion on the crafted `univ.Real` object (e.g., `prettyPrint()`, `str()`, comparison, arithmetic operation, or `float()` call).
5. During this conversion, `pyasn1` attempts exact big-integer exponentiation based on the large exponent in the REAL value.
6. This computation requires materializing an extremely large intermediate integer, leading to a rapid and uncontrolled consumption of system CPU and memory resources.
7. The application becomes unresponsive or crashes due to resource exhaustion, resulting in a denial of service for legitimate users.

## Impact

Successful exploitation of CVE-2026-59886 leads to a denial of service (DoS) for applications processing untrusted ASN.1 REAL values using `pyasn1` library versions 0.6.3 or earlier. The vulnerability causes the application to consume excessive CPU and memory, often leading to unresponsiveness or a crash. Any operation that converts the `pyasn1.type.univ.Real` object to a Python float, such as printing, logging, comparing, or performing arithmetic, can trigger this resource exhaustion. While no specific victim counts or sectors are mentioned, any Python application that handles untrusted ASN.1 REAL data via `pyasn1` is at risk of being rendered unavailable.

## Recommendation

* Patch CVE-2026-59886 by upgrading the `pyasn1` library to version 0.6.4 or later immediately.
* If immediate patching of `pyasn1` is not feasible, implement workarounds to avoid converting, printing, or comparing `pyasn1.type.univ.Real` objects from untrusted sources. Instead, inspect the raw (mantissa, base, exponent) tuple directly.
