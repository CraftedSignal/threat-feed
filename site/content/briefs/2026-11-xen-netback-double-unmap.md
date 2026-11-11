---
brief_id: brief-2026-11-11-xen-netback-double-unmap
event_id: brief-2026-11-11-xen-netback-double-unmap
revision: 1
activity_at: "2026-11-11T03:39:03Z"
title: 'Linux xen-netback: guest can trigger double unmap of memory (CVE-2026-99287)'
slug: 2026-11-xen-netback-double-unmap
description: A vulnerability in the Linux xen-netback driver allows a guest to trigger a double unmap of memory during connection setup due to a missing test when handling illegal ring index values.
date: "2026-11-11T03:39:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
tags:
  - linux
  - kernel
  - virtualization
products:
  - Linux xen-netback
cves:
  - id: CVE-2026-99287
    kev_status: "false"
references:
  - https://xenbits.xen.org/xsa/advisory-532.html
  - https://seclists.org/oss-sec/2026/q4/644
---

The Xen Security Advisory XSA-532 (CVE-2026-99287) identifies an issue in the Linux xen-netback driver. During the connection setup to a frontend, the backend maps ring pages and validates their contents. If the ring index values are illegal, the driver attempts to unmap all allocated resources; however, a missing test during this cleanup process allows a guest to trigger a double unmap of memory.
