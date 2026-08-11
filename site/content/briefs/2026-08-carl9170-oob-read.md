---
title: Out-of-Bounds Read in carl9170 Wi-Fi Driver
slug: 2026-08-carl9170-oob-read
description: The carl9170 Wi-Fi driver contains an out-of-bounds read vulnerability due to an off-by-two error in the TX status handler, potentially leading to memory disclosure or system instability.
date: "2026-08-11T09:58:18Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - informational
  - product-news
products:
  - carl9170
cves:
  - id: CVE-2026-68350
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-68350
---

The carl9170 wireless driver, commonly used in Linux-based kernel environments, contains a security flaw identified as CVE-2026-68350. The vulnerability originates from an off-by-two error within the TX status handler, which manages wireless frame transmission reporting. This logic error allows the driver to perform an out-of-bounds (OOB) memory read. 

For defenders and infrastructure security teams, this vulnerability represents a risk primarily in systems utilizing hardware supported by the carl9170 driver, such as specific USB wireless adapters. While the primary impact involves kernel-level memory disclosure or potential system crashes (Denial of Service), the exploitability depends on an attacker's ability to send or influence specially crafted 802.11 frames that trigger the flawed TX status logic. As of this report, no specific in-the-wild exploitation is documented.

## Impact

Successful exploitation of this vulnerability could lead to the exposure of sensitive kernel memory, potentially leaking cryptographic keys or other system information. Additionally, the out-of-bounds read may trigger a kernel panic, leading to a localized Denial of Service on the affected host. The impact is most significant in environments where the host is exposed to untrusted wireless traffic.

## Recommendation

Prioritize the application of kernel security updates provided by the relevant Linux distribution vendors that maintain the carl9170 driver. Monitor system logs for kernel panics or driver-related errors originating from the carl9170 module, as these may indicate exploitation attempts causing system instability.
