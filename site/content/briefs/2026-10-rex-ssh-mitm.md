---
brief_id: brief-2026-10-22-rex-ssh-mitm
event_id: brief-2026-10-22-rex-ssh-mitm
revision: 1
activity_at: "2026-10-22T01:36:35Z"
title: 'Rex: SSH host key vulnerability (CVE-2026-94140)'
slug: 2026-10-rex-ssh-mitm
description: Rex versions through 1.16.1 for Perl accept unknown SSH host keys during remote rsync transfers due to a hardcoded StrictHostKeyChecking=no configuration.
date: "2026-10-22T01:36:35Z"
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
  - cpe:2.3:a:rex:rex:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ssh
  - rsync
vendors:
  - Rex
products:
  - Rex (through 1.16.1)
cves:
  - id: CVE-2026-94140
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/299
---

Rex versions through 1.16.1 for Perl hardcode 'StrictHostKeyChecking=no', which causes the application to accept unknown SSH host keys when performing remote rsync transfers.
