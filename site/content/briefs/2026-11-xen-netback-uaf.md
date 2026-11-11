---
brief_id: brief-2026-11-10-xen-netback-uaf
event_id: brief-2026-11-10-xen-netback-uaf
revision: 1
activity_at: "2026-11-10T21:35:13Z"
title: 'Xen: Linux xen-netback use-after-free in network statistics (CVE-2026-99286)'
slug: 2026-11-xen-netback-uaf
description: A use-after-free vulnerability in the Linux xen-netback driver exists due to missing RCU synchronization during queue teardown.
date: "2026-11-10T21:35:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
cpes:
  - cpe:2.3:a:linux:xen_netback:*:*:*:*:*:*:*:*
vendors:
  - Linux
products:
  - xen-netback (kernel driver)
cves:
  - id: CVE-2026-99286
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/643
---

The Linux xen-netback driver contains a use-after-free vulnerability (CVE-2026-99286) related to network statistics. The issue occurs when tearing down queues after an error during connection to the frontend - such as illegal Xenstore data provided by a guest - due to missing RCU synchronization before freeing the network statistics data.
