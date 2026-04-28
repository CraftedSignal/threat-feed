---
title: Tenda F456 Remote Buffer Overflow Vulnerability
slug: 2024-01-tenda-f456-buffer-overflow
description: A remote buffer overflow vulnerability exists in Tenda F456 version 1.0.0.5 via manipulation of the 'page' argument in the fromDhcpListClient function of the /goform/DhcpListClient component, potentially leading to arbitrary code execution.
date: "2024-01-02T12:00:00Z"
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

A critical buffer overflow vulnerability, identified as CVE-2026-7098, has been discovered in Tenda F456 router version 1.0.0.5. The vulnerability resides within the `fromDhcpListClient` function of the `/goform/DhcpListClient` component's `httpd` service. An attacker can exploit this flaw by remotely manipulating the `page` argument, leading to a buffer overflow. Publicly available exploit code exists, increasing the risk of widespread exploitation. Successful exploitation could allow an…
