---
title: Samsung Exynos Processor Denial-of-Service Vulnerability (CVE-2025-57834)
slug: 2026-04-exynos-dos
description: A denial-of-service vulnerability, CVE-2025-57834, exists in Samsung Exynos processors and modems due to improper input validation, potentially leading to device malfunction or service disruption.
date: "2026-04-06T20:16:20Z"
severities:
  - high
tags:
  - cve-2025-57834
  - denial-of-service
  - samsung
  - exynos
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2025-57834
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-57834
  - https://semiconductor.samsung.com/support/quality-support/product-security-updates/
  - https://semiconductor.samsung.com/support/quality-support/product-security-updates/cve-2025-54328/
ioc_counts:
  email: 1
rules:
  - title: Detect Repeated Connections to a Potentially Vulnerable Device
    description: Detects a high number of connections to a device that might be running a vulnerable Exynos processor, indicating a potential denial of service attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - firewall
  - title: Detect Abnormal Process Termination on Affected Devices
    description: Detects processes crashing or terminating unexpectedly on devices with Exynos processors, which could be a sign of a denial-of-service exploit.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2025-57834 is a denial-of-service vulnerability affecting a wide range of Samsung Exynos processors and modems, including the Exynos 980, 850, 990, 1080, 2100, 1280, 2200, 1330, 1380, 1480, 2400, 1580, 2500, 1680, 9110, W920, W930, W1000, Modem 5123, Modem 5300, Modem 5400, and Modem 5410. The vulnerability stems from a lack of proper input validation, allowing a malicious actor to send crafted input that triggers a denial-of-service condition. This could potentially lead to device…
