---
title: NULL Pointer Dereference Vulnerability in MediaTek mt76 Wi-Fi Driver
slug: 2026-08-mt76-null-ptr
description: A NULL pointer dereference vulnerability exists in the MediaTek mt76 driver within the mt76_connac_mcu_uni_bss_he_tlv function, potentially leading to kernel panic or denial-of-service conditions.
date: "2026-08-11T10:08:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - kernel
  - firmware
vendors:
  - MediaTek
products:
  - mt76
cves:
  - id: CVE-2026-68309
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68309
---

CVE-2026-68309 identifies a security vulnerability within the mt76 kernel driver used for MediaTek Wi-Fi chipsets. The issue is located in the `mt76_connac_mcu_uni_bss_he_tlv()` function. A lack of proper validation when processing BSS HE (High Efficiency) TLV data structures can lead to a NULL pointer dereference. This flaw is triggered during the processing of wireless management frames or specific hardware communication packets. If exploited, an attacker capable of sending specially crafted frames to the affected wireless interface could cause the kernel to crash, resulting in a system denial-of-service. This vulnerability primarily affects devices utilizing the MediaTek mt76 driver stack, which is commonly found in Linux-based wireless network hardware.

## Impact

Successful exploitation of this vulnerability results in kernel instability, typically manifesting as a system crash or hang. This denial-of-service condition affects the availability of the network interface and the host system. As the driver operates within the kernel space, this flaw poses a risk to devices ranging from embedded Wi-Fi access points to laptops and IoT devices relying on MediaTek chipsets for wireless connectivity.

## Recommendation

1. Patch the Linux kernel or firmware associated with MediaTek mt76 drivers to the version addressing CVE-2026-68309.
2. Implement kernel hardening measures, such as enabling PAN (Privileged Access Never) or SMAP (Supervisor Mode Access Prevention), to mitigate the impact of kernel-level pointer dereference vulnerabilities.
3. Monitor system logs for kernel oops or panic messages specifically referencing the mt76 driver during periods of high wireless traffic.
