---
title: eswifi Socket Offload Driver Buffer Overflow Vulnerability (CVE-2026-1679)
slug: 2026-03-eswifi-buffer-overflow
description: CVE-2026-1679 describes a vulnerability in the eswifi socket offload driver where user-provided payloads are copied into a fixed buffer without proper size checking, leading to a buffer overflow and kernel memory corruption.
date: "2026-03-28T00:16:04Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-1679
  - buffer-overflow
  - kernel-memory-corruption
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1679
  - https://github.com/zephyrproject-rtos/zephyr/security/advisories/GHSA-qx3g-5g22-fq5w
rules:
  - title: Detect Suspicious Socket Send API Calls (eswifi)
    description: Detects potential exploitation attempts of CVE-2026-1679 by monitoring for socket send API calls from unusual processes that may be attempting to trigger the buffer overflow in the eswifi driver.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Kernel Memory Corruption (Hypothetical)
    description: This rule (hypothetical) aims to detect kernel memory corruption which could be a result of exploiting CVE-2026-1679. This requires a memory dump analysis capability from the host.
    platform: sigma
    severity: critical
    tactics:
      - denial_of_service
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_memory
      - linux
rules_count: 2
---

CVE-2026-1679 is a buffer overflow vulnerability affecting the eswifi socket offload driver. The vulnerability arises because the driver copies user-provided payloads into a fixed-size buffer without validating the input size. This can lead to an overflow of the `eswifi->buf` buffer, resulting in corruption of kernel memory (CWE-120). The Zephyr Project assigned a CVSS v3.1 score of 7.3 to this vulnerability. Exploitation requires local code execution to call the socket send API; it is not…
