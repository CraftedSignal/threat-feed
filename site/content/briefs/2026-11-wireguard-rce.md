---
brief_id: brief-2026-11-03-wireguard-rce
event_id: brief-2026-11-03-wireguard-rce
revision: 1
activity_at: "2026-11-03T09:57:01Z"
title: 'WireGuard: Improper input validation leads to remote command execution (CVE-2026-105980)'
slug: 2026-11-wireguard-rce
description: A vulnerability in the WireGuard VPN function involving improper input validation allows a remote attacker with high privileges to inject and execute system commands with root privileges.
date: "2026-11-03T09:57:01Z"
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
  - WireGuard
cves:
  - id: CVE-2026-105980
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105980
---

CVE-2026-105980 identifies an improper input validation vulnerability within the WireGuard VPN function. The flaw allows a remote attacker with high privileges to inject system commands and execute them with root privileges.
