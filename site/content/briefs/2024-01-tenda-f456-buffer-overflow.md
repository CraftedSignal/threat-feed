---
title: Tenda F456 Remote Buffer Overflow Vulnerability
slug: 2024-01-tenda-f456-buffer-overflow
description: A remote buffer overflow vulnerability exists in Tenda F456 version 1.0.0.5 via manipulation of the 'page' argument in the fromDhcpListClient function of the /goform/DhcpListClient component, potentially leading to arbitrary code execution.
date: "2024-01-02T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-7098
  - buffer-overflow
  - router
vendors:
  - Tenda
products:
  - F456
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-7098
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7098
rules:
  - title: Detect Tenda F456 Buffer Overflow Attempt
    description: Detects attempts to exploit the Tenda F456 buffer overflow vulnerability by monitoring for unusually long 'page' parameters in requests to /goform/DhcpListClient.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F456 Buffer Overflow Response
    description: Detects potential successful exploitation of the Tenda F456 buffer overflow vulnerability based on unexpected server response codes (e.g., 500 Internal Server Error) after a request to /goform/DhcpListClient with a long page parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical buffer overflow vulnerability, identified as CVE-2026-7098, has been discovered in Tenda F456 router version 1.0.0.5. The vulnerability resides within the `fromDhcpListClient` function of the `/goform/DhcpListClient` component's `httpd` service. An attacker can exploit this flaw by remotely manipulating the `page` argument, leading to a buffer overflow. Publicly available exploit code exists, increasing the risk of widespread exploitation. Successful exploitation could allow an attacker to execute arbitrary code on the device, potentially gaining full control of the router and the network it serves. This poses a significant threat to home and small business users relying on these routers.

## Attack Chain

1.  Attacker identifies a vulnerable Tenda F456 router (version 1.0.0.5) accessible over the network.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/DhcpListClient` endpoint.
3.  The crafted request includes a `page` argument with a payload designed to overflow the buffer in the `fromDhcpListClient` function.
4.  The `httpd` service processes the request and calls the `fromDhcpListClient` function.
5.  Due to insufficient bounds checking, the oversized payload overwrites the buffer, potentially overwriting adjacent memory regions.
6.  The attacker's payload overwrites the return address on the stack with a pointer to attacker-controlled code.
7.  The `fromDhcpListClient` function returns, causing execution to jump to the attacker-controlled code.
8.  The attacker-controlled code executes with the privileges of the `httpd` service, potentially allowing for full control of the device.

## Impact

Successful exploitation of this vulnerability can allow a remote attacker to execute arbitrary code on the Tenda F456 router. This could lead to a complete compromise of the device, allowing the attacker to modify router settings, intercept network traffic, or use the router as a pivot point for further attacks within the network. Given the ease of exploitation and public availability of exploit code, a large number of Tenda F456 users are at risk.

## Recommendation

*   Monitor web server logs for suspicious requests to `/goform/DhcpListClient` with unusually long `page` parameters to detect potential exploitation attempts (see Sigma rule "Detect Tenda F456 Buffer Overflow Attempt").
*   Implement rate limiting on requests to the `/goform/DhcpListClient` endpoint to mitigate the impact of potential attacks.
*   Deploy the Sigma rule "Detect Tenda F456 Buffer Overflow Response" to identify successful exploitation attempts based on server response codes.
