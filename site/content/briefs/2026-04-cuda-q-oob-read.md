---
title: NVIDIA CUDA-Q Out-of-Bounds Read Vulnerability (CVE-2026-24189)
slug: 2026-04-cuda-q-oob-read
description: NVIDIA CUDA-Q is vulnerable to an out-of-bounds read via a maliciously crafted request to an endpoint, potentially leading to denial of service and information disclosure as tracked by CVE-2026-24189.
date: "2026-04-21T17:16:23Z"
severities:
  - high
tags:
  - cve-2026-24189
  - out-of-bounds read
  - nvidia
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24189
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5820
  - https://www.cve.org/CVERecord?id=CVE-2026-24189
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious CUDA-Q HTTP Requests
    description: Detects potentially malicious HTTP requests targeting CUDA-Q endpoints that may indicate an out-of-bounds read attempt.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Possible CUDA-Q Out-of-Bounds Read via HTTP Status
    description: Detects unusual HTTP status codes that may indicate a server error resulting from an out-of-bounds read attempt against CUDA-Q.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

NVIDIA CUDA-Q contains a vulnerability identified as CVE-2026-24189 that allows an unauthenticated attacker to trigger an out-of-bounds read. This vulnerability exists in an unspecified endpoint of the CUDA-Q software. By sending a maliciously crafted request, an attacker can potentially read sensitive information from memory or cause a denial-of-service condition. This vulnerability has a CVSS v3.1 score of 8.2, indicating a high severity. Successful exploitation can lead to both information…
