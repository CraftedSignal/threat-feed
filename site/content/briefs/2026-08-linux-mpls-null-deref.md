---
title: Linux Kernel MPLS NULL Pointer Dereference Vulnerability
slug: 2026-08-linux-mpls-null-deref
description: A NULL pointer dereference vulnerability in the Linux kernel's MPLS subsystem, specifically affecting configurations where CONFIG_INET is disabled, can lead to a denial-of-service condition.
date: "2026-08-09T09:34:56Z"
lastmod: "2026-08-11T09:55:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - linux
  - kernel
  - informational
  - stability
  - cve
  - filesystem
  - product-news
  - denial-of-service
  - kernel-vulnerability
vendors:
  - Linux Foundation
products:
  - Linux Kernel
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in the Btrfs filesystem implementation within the Linux kernel allows for a potential denial of service or privilege escalation.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: The issue arises from insufficient validation of the free space cache, where an attacker can craft a filesystem image with more entries than pages, potentially leading to memory corruption or instability.
    confidence_band: high
cves:
  - id: CVE-2026-64569
    epss: 0.00156
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64569
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64583
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64576
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64574
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64579
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64580
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64542
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64567
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-64581
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68258
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68203
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68190
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68363
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68242
updates:
  - at: "2026-08-11T09:51:30Z"
    level: L1
    summary: added coverage for Linux Kernel
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68258
  - at: "2026-08-11T09:51:36Z"
    level: L1
    summary: added coverage for Linux kernel
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68203
  - at: "2026-08-11T09:52:02Z"
    level: L1
    summary: added coverage for Linux Kernel
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68190
  - at: "2026-08-11T09:54:38Z"
    level: L1
    summary: added coverage for Linux kernel
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68363
  - at: "2026-08-11T09:55:04Z"
    level: L1
    summary: added coverage for Linux Kernel
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68242
---

CVE-2026-64569 describes a vulnerability in the Linux kernel's Multiprotocol Label Switching (MPLS) subsystem. The issue resides in the mpls_valid_fib_dump_req function, which handles validation for FIB dump requests. Research indicates that when the kernel is compiled with CONFIG_INET=n, the function attempts to dereference a NULL pointer, causing a kernel panic and subsequent denial-of-service (DoS) condition. This vulnerability is specific to custom kernel configurations where networking support is stripped of the standard INET protocol suite while retaining MPLS functionality. Defending against this requires kernel updates to address the improper validation logic within the network stack.

## Impact

The vulnerability poses a denial-of-service risk for systems utilizing non-standard Linux kernel configurations (CONFIG_INET=n) that employ MPLS. An attacker with the ability to trigger a FIB dump request could crash the kernel, resulting in system instability or downtime. While the scope is limited to specific custom builds, affected systems such as embedded devices or specialized network appliances may be at risk of localized service disruption.

## Recommendation

- Audit systems using custom Linux kernel builds to determine if CONFIG_INET is disabled and MPLS is enabled.
- Apply the vendor-provided patch for the Linux kernel to resolve the NULL pointer dereference in mpls_valid_fib_dump_req.
- Monitor kernel logs for recurring panic events or unexpected reboots associated with network configuration changes.
