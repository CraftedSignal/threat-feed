---
title: NULL Pointer Dereference in Linux ath11k Wi-Fi Driver
slug: 2026-08-ath11k-null-dereference
description: CVE-2026-68362 describes a NULL pointer dereference vulnerability in the Linux kernel ath11k driver that may lead to denial-of-service or potential code execution via crafted interactions.
date: "2026-08-11T09:57:18Z"
lastmod: "2026-08-11T10:00:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - kernel-vulnerability
  - denial-of-service
  - vulnerability
  - linux-kernel
  - networking
  - cve-2026-68355
products:
  - ath11k
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This flaw could potentially allow a local attacker to cause a denial-of-service condition or execute arbitrary code by triggering a kernel panic through crafted interactions with the wireless driver.
    confidence_band: med
cves:
  - id: CVE-2026-68362
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68362
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68355
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: medium_term
      action: Patch Linux kernel packages containing the fix for CVE-2026-68362.
      owner: IT Operations
      addresses: CVE-2026-68362
      evidence: Source confirms a fix is required for the identified vulnerability.
updates:
  - at: "2026-08-11T10:00:50Z"
    level: L1
    summary: added coverage for ath11k
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68355
---

CVE-2026-68362 concerns a vulnerability identified in the Linux kernel within the ath11k driver, specifically affecting the `ath11k_hal_srng_access_begin` function. This vulnerability is classified as a NULL pointer dereference, which occurs when the driver fails to properly validate pointers during service ring (SRNG) access operations. An attacker with local access to the system, or potentially through specific interfaces interacting with the wireless hardware, could trigger this flaw to cause a kernel panic, resulting in a denial-of-service (DoS) condition. While kernel-level memory corruption vulnerabilities can sometimes be leveraged for local privilege escalation or arbitrary code execution, this flaw is primarily documented as a stability issue in the underlying Wi-Fi driver code. Defenders should monitor for kernel-related stability reports on devices utilizing ath11k-based hardware.

## Impact

The impact of this vulnerability is primarily focused on system availability, where successful exploitation results in a kernel panic and system crash. The vulnerability affects users and devices relying on the Linux kernel ath11k driver for Wi-Fi connectivity. While arbitrary code execution is theoretically possible through sophisticated exploitation of memory corruption, the current assessment focuses on the potential for service disruption across affected Linux-based platforms.

## Recommendation

- Identify all systems running the Linux kernel utilizing the ath11k wireless driver.
- Apply the relevant Linux distribution security patches that address CVE-2026-68362 as they become available.
- Monitor system logs for repeated kernel oops or panic messages associated with `ath11k` driver modules.
