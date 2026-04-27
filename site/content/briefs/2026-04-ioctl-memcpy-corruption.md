---
title: Qualcomm IOCTL Memory Corruption Vulnerability
slug: 2026-04-ioctl-memcpy-corruption
description: A memory corruption vulnerability (CVE-2026-21372) exists when processing IOCTL requests with invalid buffer sizes leading to a heap-based buffer overflow, reported by Qualcomm with a CVSS v3.1 score of 7.8.
date: "2026-04-06T16:16:29Z"
severities:
  - high
actors:
  - Qualcomm
tags:
  - cve-2026-21372
  - memory-corruption
  - heap-overflow
  - ioctl
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-21372
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21372
  - https://docs.qualcomm.com/product/publicresources/securitybulletin/april-2026-bulletin.html
ioc_counts:
  email: 1
rules:
  - title: Potential IOCTL Heap Overflow Attempt
    description: Detects potential attempts to exploit heap overflows via IOCTL calls by monitoring memcpy operations in proximity to IOCTL calls within a short timeframe.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Process with memcpy Operation
    description: Detects potential attempts to exploit memory corruption via memcpy operations.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-21372 describes a memory corruption vulnerability affecting systems that handle IOCTL requests, specifically during memcpy operations. The vulnerability arises when the system does not properly validate buffer sizes, leading to a heap-based buffer overflow (CWE-122). This flaw can be triggered by sending IOCTL requests with invalid buffer sizes, potentially allowing an attacker with local access to execute arbitrary code or cause a denial-of-service condition. Qualcomm reported this…
