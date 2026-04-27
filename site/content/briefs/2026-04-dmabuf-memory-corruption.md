---
title: Memory Corruption Vulnerability in DMABUF IOCTL Calls (CVE-2026-21380)
slug: 2026-04-dmabuf-memory-corruption
description: A use-after-free vulnerability, identified as CVE-2026-21380, exists due to memory corruption when using deprecated DMABUF IOCTL calls for video memory management, potentially leading to arbitrary code execution.
date: "2026-04-06T16:16:30Z"
severities:
  - high
tags:
  - cve-2026-21380
  - memory-corruption
  - use-after-free
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-21380
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-21380
  - https://docs.qualcomm.com/product/publicresources/securitybulletin/april-2026-bulletin.html
rules:
  - title: Detect Suspicious Process Making DMABUF IOCTL Calls
    description: Detects processes making ioctl calls that may be related to DMABUF, indicating potential exploit attempts of CVE-2026-21380
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect suspicious file access to /dev/dri/card*
    description: Detects processes accessing DRM card devices, often used for DMABUF operations
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-21380 describes a critical use-after-free vulnerability impacting systems that utilize DMABUF IOCTL calls for video memory management. This vulnerability, reported by Qualcomm, arises from improper handling of memory when these deprecated calls are used. Successful exploitation could allow a local attacker with low privileges to corrupt memory, leading to potential arbitrary code execution or denial-of-service conditions. The vulnerability was published on April 6, 2026, and is…
