---
brief_id: brief-2026-10-28-samsung-exynos-sms-overflow
event_id: brief-2026-10-28-samsung-exynos-sms-overflow
revision: 1
activity_at: "2026-10-28T19:23:59Z"
title: 'Samsung Exynos 980 Firmware: SMS Parser Stack Buffer Overflow (CVE-2025-54328)'
slug: 2026-10-samsung-exynos-sms-overflow
description: A stack-based buffer overflow exists in the Samsung Exynos 980 firmware's SMS RP-DATA parser, enabling potential zero-click remote code execution on the baseband. A conceptual proof-of-concept (PoC) exploit has been published.
date: "2026-10-28T19:23:59Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: C
  credibility: "3"
  rating: C3
  likelihood: roughly even chance
cpes:
  - cpe:2.3:o:samsung:exynos_980_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_990_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_850_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1080_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_2100_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1280_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1330_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1380_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1480_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_1580_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_2200_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_2400_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_2500_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_9110_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_w930_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_w920_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_w1000_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_modem_5123_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_modem_5300_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:samsung:exynos_modem_5400_firmware:-:*:*:*:*:*:*:*
vendors:
  - Samsung
products:
  - Exynos 980 Firmware
cves:
  - id: CVE-2025-54328
    cvss: 10
    epss: 0.0052
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HUNT-BENITO-SAMSUNG-EXYNOS-SMS-STACK-OVERFLOW-CVE-2025-54328-CRITICAL-ZERO-CLICK-BASEBAND-RCE
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HUNT-BENITO-SAMSUNG-EXYNOS-SMS-STACK-OVERFLOW-CVE-2025-54328-CRITICAL-ZERO-CLICK-BASEBAND-RCE&utm_source=rss&utm_medium=rss
---

CVE-2025-54328 is a stack-based buffer overflow in the SMS RP-DATA parser of Samsung Exynos 980 firmware. The vulnerability is reported as a zero-click, remote code execution (RCE) flaw affecting the baseband. A conceptual PoC has been published that generates a raw RP-DATA message with an oversized TPDU payload intended to trigger the overflow. The PoC documentation notes that successful exploitation requires target-specific memory layout and firmware gadget addresses.
