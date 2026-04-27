---
title: Mesa WebGPU Out-of-Bounds Write Vulnerability (CVE-2026-40393)
slug: 2026-04-mesa-webgpu-oob-write
description: An out-of-bounds write vulnerability exists in Mesa versions before 25.3.6 and 26 before 26.0.1 due to an untrusted allocation size in WebGPU, potentially leading to code execution.
date: "2026-04-12T19:16:20Z"
severities:
  - high
tags:
  - cve
  - vulnerability
  - webgpu
cves:
  - id: CVE-2026-40393
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40393
  - https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/39866
  - https://lists.freedesktop.org/archives/mesa-dev/2026-February/226597.html
rules:
  - title: Detect Suspicious WebGPU Commands in Web Server Logs
    description: Detects potential exploitation attempts of WebGPU vulnerabilities by monitoring for suspicious commands in web server logs.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Mesa library loading
    description: Detects when the vulnerable Mesa library is loaded, which can indicate a system that may be vulnerable.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - image_load
      - linux
rules_count: 2
---

CVE-2026-40393 is a critical vulnerability affecting Mesa, an open-source graphics library, specifically impacting the WebGPU component. The vulnerability stems from insufficient validation of the amount of data to be allocated, allowing an attacker to influence the allocation size via an untrusted party. This value is subsequently passed to the `alloca` function, resulting in a heap out-of-bounds write. The vulnerability affects Mesa versions prior to 25.3.6 and 26 prior to 26.0.1. Successful…
