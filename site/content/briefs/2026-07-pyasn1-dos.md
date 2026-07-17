---
title: 'pyasn1: Quadratic Complexity in OBJECT IDENTIFIER and RELATIVE-OID Processing Allows Denial of Service'
slug: 2026-07-pyasn1-dos
description: A denial of service vulnerability, identified as CVE-2026-59885, exists in the pyasn1 library caused by quadratic complexity in the processing of OBJECT IDENTIFIER and RELATIVE-OID, which can lead to a denial of service.
date: "2026-07-17T07:11:02Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - library
vendors:
  - pyasn1
products:
  - pyasn1
cves:
  - id: CVE-2026-59885
    cvss: 7.5
    epss: 0.00339
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-59885
---

CVE-2026-59885 is a denial-of-service vulnerability affecting the `pyasn1` library. This vulnerability stems from quadratic complexity in how the library processes `OBJECT IDENTIFIER` and `RELATIVE-OID` data structures. An attacker can craft malicious ASN.1 data inputs that, when processed by `pyasn1`, consume excessive CPU resources due to the inefficient parsing algorithm, leading to a denial of service for applications or services relying on the library for ASN.1 data handling. This can disrupt services that use `pyasn1` for cryptographic operations, certificate validation, or network protocol parsing. The specific versions affected are not detailed in the MSRC brief, but users of `pyasn1` should review their implementations and update promptly.

## Attack Chain

1. An attacker identifies a target system or application that uses the `pyasn1` library to process ASN.1 encoded data from untrusted sources.
2. The attacker crafts a malformed or excessively complex `OBJECT IDENTIFIER` or `RELATIVE-OID` within an ASN.1 data structure.
3. The attacker sends this specially crafted ASN.1 data to the vulnerable application.
4. When the `pyasn1` library attempts to parse the malicious `OBJECT IDENTIFIER` or `RELATIVE-OID` field, its quadratic complexity processing algorithm is triggered.
5. This leads to the application consuming excessive CPU resources and memory as it attempts to parse the malformed data.
6. The application becomes unresponsive or crashes due to resource exhaustion.
7. The result is a denial-of-service condition for the target application or system, rendering it unavailable.

## Impact

A successful exploitation of CVE-2026-59885 would result in affected applications or services becoming unavailable due to resource exhaustion, specifically excessive CPU and memory consumption. Organizations relying on the `pyasn1` library for critical functions, such as authentication mechanisms, secure communication channels, or data parsing from external inputs, could experience significant operational disruption, data processing delays, and potential business losses. While no specific victims or targeting details are provided, any system processing untrusted ASN.1 data with a vulnerable `pyasn1` version is at risk of service interruption.

## Recommendation

* Patch CVE-2026-59885 by updating the `pyasn1` library to a version that addresses this quadratic complexity vulnerability immediately.
* Review applications that process `OBJECT IDENTIFIER` and `RELATIVE-OID` data using `pyasn1` to understand potential exposure and ensure input validation.
