---
title: Samsung Exynos Wi-Fi Driver Use-After-Free Vulnerability (CVE-2025-54602)
slug: 2026-04-exynos-wifi-uaf
description: A use-after-free vulnerability exists in the Wi-Fi driver of Samsung Mobile and Wearable Processors Exynos 980, 850, 1080, 1280, 1330, 1380, 1480, 1580, W920, W930, and W1000 due to improper synchronization on a global variable, allowing attackers to trigger a race condition and potentially execute arbitrary code.
date: "2026-04-06T20:16:20Z"
severities:
  - high
tags:
  - cve-2025-54602
  - use-after-free
  - exynos
  - samsung
  - wifi
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2025-54602
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-54602
  - https://semiconductor.samsung.com/support/quality-support/product-security-updates/
  - https://semiconductor.samsung.com/support/quality-support/product-security-updates/cve-2025-54602/
rules:
  - title: Detect Concurrent IOCTL Calls to Wi-Fi Driver
    description: Detects multiple threads invoking ioctl functions concurrently, potentially indicating an attempt to trigger the race condition related to CVE-2025-54602.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Process Accessing Wi-Fi Driver Memory Region
    description: Detects processes attempting to access memory regions associated with the Wi-Fi driver after it has been freed, indicative of a use-after-free vulnerability exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2025-54602 is a use-after-free vulnerability affecting the Wi-Fi driver in Samsung Mobile Processor and Wearable Processor Exynos chipsets. This vulnerability impacts the following Exynos models: 980, 850, 1080, 1280, 1330, 1380, 1480, 1580, W920, W930, and W1000. The root cause is an improper synchronization on a global variable within the driver, leading to a potential use-after-free scenario. An attacker can exploit this vulnerability by triggering a race condition through concurrent…
