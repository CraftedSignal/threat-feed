---
brief_id: brief-2026-11-04-qihoo-360-os-command-injection
event_id: brief-2026-11-04-qihoo-360-os-command-injection
revision: 1
activity_at: "2026-11-04T02:27:15Z"
title: 'Qihoo 360 Routers: OS Command Injection (CVE-2026-121608)'
slug: 2026-11-qihoo-360-os-command-injection
description: A remote OS command injection vulnerability exists in the Timezone Push Handler of specific Qihoo 360 router models.
date: "2026-11-04T02:27:15Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
products:
  - Qihoo 360 D603-2 (<= 6.3.2)
  - Qihoo 360 D600-2 (<= 6.3.2)
  - Qihoo 360 D606-6 (<= 6.3.2)
cves:
  - id: CVE-2026-121608
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121608
---

A vulnerability (CVE-2026-121608) has been identified in Qihoo 360 models D603-2, D600-2, and D606-6 up to version 6.3.2. The issue resides in the 'on_push_message' function of '/fs2/bin/iscm' within the Timezone Push Handler. Manipulation of the 'tz' argument can lead to OS command injection. This attack can be launched remotely, and the exploit has been publicly disclosed. Firmware version 6.4.0 includes a check_timezone_parameter validation to resolve the issue.
