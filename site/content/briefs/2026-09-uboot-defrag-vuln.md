---
title: Out-of-Bounds Write Vulnerability in U-Boot IP Defragmentation
slug: 2026-09-uboot-defrag-vuln
description: An out-of-bounds write vulnerability in the U-Boot __net_defragment() function allows remote attackers to corrupt memory and cause a denial-of-service during netboot operations.
date: "2026-09-29T22:29:57Z"
lastmod: "2026-09-29T22:30:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:denx:u-boot:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - bootloader
  - denial-of-service
vendors:
  - U-Boot
products:
  - U-Boot (< 2026.10-rc3)
  - U-Boot (< 2026.10-rc5)
cves:
  - id: CVE-2026-71971
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71971
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74225
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update U-Boot firmware to version 2026.10-rc3 or later
      owner: IT Operations
      addresses: CVE-2026-71971
      evidence: NVD vulnerability entry recommends updating to versions containing the fix
updates:
  - at: "2026-09-29T22:30:21Z"
    level: L2
    summary: added coverage for U-Boot (< 2026.10-rc5)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74225
---

A memory corruption vulnerability, tracked as CVE-2026-71971, affects U-Boot versions prior to 2026.10-rc3 when the CONFIG_IP_DEFRAG feature is enabled. The flaw resides in the __net_defragment() function within net/net.c. During the network boot process, an attacker can transmit specially crafted IP fragments containing a non-zero offset and the More-Fragments flag. When processed by the bootloader, these fragments trigger an out-of-bounds write operation, leading to memory corruption. This vulnerability is significant for embedded environments utilizing network-based boot mechanisms, as successful exploitation results in an immediate crash of the bootloader, preventing the system from booting and effectively resulting in a permanent denial-of-service condition until manual recovery is performed on the affected hardware.

## Impact

The vulnerability poses a severe risk to embedded systems that rely on U-Boot for network booting, such as networking equipment, industrial control systems, and IoT devices. Successful exploitation causes a complete bootloader failure, rendering devices unreachable and non-functional. Given that these devices often operate in headless or remote environments, the impact of such a denial-of-service event necessitates physical intervention to restore operational status, potentially causing widespread service disruption.

## Recommendation

Prioritize the identification of embedded devices within the infrastructure that utilize U-Boot with the CONFIG_IP_DEFRAG feature enabled. Update all vulnerable firmware components to U-Boot version 2026.10-rc3 or later as soon as the upstream vendor releases patched builds. In environments where patching is not immediately feasible, restrict network access to the boot sequence by isolating systems that require network-based booting to trusted, physically secured management networks to mitigate the risk of remote fragment injection.
