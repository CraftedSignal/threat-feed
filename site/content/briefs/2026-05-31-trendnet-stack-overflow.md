---
brief_id: brief-2026-05-31-trendnet-stack-overflow
event_id: brief-2026-05-31-trendnet-stack-overflow
revision: 2
activity_at: "2026-05-31T03:20:53Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:e7cd65458eb820ff83b866cec88cf9456b1c0375f022a6da26f699dbfa87ddec
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: TRENDnet TEW-432BRP Stack-Based Buffer Overflow Vulnerability (CVE-2026-10162)
slug: 2026-05-31-trendnet-stack-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-10162) exists in the formSetPassword function of TRENDnet TEW-432BRP version 3.10B20, allowing a remote attacker to execute arbitrary code by manipulating the webpage argument in the /goform/formSetPassword file.
date: "2026-05-31T03:20:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
tags:
  - stack-based-buffer-overflow
  - rce
  - cve-2026-10162
vendors:
  - TRENDnet
products:
  - TEW-432BRP 3.10B20
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1213
    technique_name: Data from Information Repositories
cves:
  - id: CVE-2026-10162
    cvss: 8.8
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10162
rules:
  - title: Detect CVE-2026-10162 Exploitation Attempt
    description: Detects CVE-2026-10162 exploitation attempt — HTTP POST request to formSetPassword
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1213
    data_sources:
      - webserver
  - title: Detect CVE-2026-10162 Stack Buffer Overflow in TRENDnet Router
    description: Detects CVE-2026-10162 exploitation — overly long webpage parameter
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1213
    data_sources:
      - webserver
rules_count: 2
---

A stack-based buffer overflow vulnerability, identified as CVE-2026-10162, has been discovered in TRENDnet TEW-432BRP router, version 3.10B20. This flaw resides within the `formSetPassword` function of the `/goform/formSetPassword` file. An unauthenticated, remote attacker can exploit this vulnerability by crafting a malicious HTTP request containing an overly long `webpage` argument. Successful exploitation allows the attacker to overwrite parts of the stack, leading to arbitrary code execution on the device. The vendor has stated that the product has been end-of-life (EOL) since 2009 and will not be providing a patch, which increases the risk for users who are still operating this device. The exploit has been published, increasing the likelihood of exploitation.

## Attack Chain

1.  The attacker identifies a TRENDnet TEW-432BRP router version 3.10B20 exposed to the internet.
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/formSetPassword` endpoint.
3.  The crafted request includes the `webpage` parameter with a value exceeding the expected buffer size.
4.  The router's web server processes the request and passes the `webpage` parameter to the `formSetPassword` function without proper bounds checking.
5.  The `formSetPassword` function copies the oversized `webpage` argument onto the stack, overflowing the allocated buffer.
6.  The overflow overwrites adjacent memory on the stack, including the return address of the function.
7.  The function returns, but instead of returning to the caller, it jumps to an address controlled by the attacker.
8.  The attacker injects shellcode into the overflowed buffer and redirects execution to this shellcode, gaining remote code execution on the device.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the TRENDnet TEW-432BRP router. This can lead to a complete compromise of the device, including unauthorized access to network resources, modification of router settings, and potential use of the device as a botnet node. Given the age of the affected device and its end-of-life status, impacted users are unlikely to receive patches and remain vulnerable until the device is replaced or removed from service.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-10162 Exploitation Attempt` to detect attempts to exploit this vulnerability based on the URI and method.
*   Implement the Sigma rule `Detect CVE-2026-10162 Stack Buffer Overflow in TRENDnet Router` to detect overly long values for the webpage parameter.
*   Given the EOL status of TRENDnet TEW-432BRP 3.10B20, replace affected devices immediately.
*   If device replacement is not possible, isolate the device from the network and restrict access to prevent potential exploitation.
