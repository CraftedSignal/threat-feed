---
brief_id: brief-2026-11-03-linux-network-discovery
event_id: brief-2026-11-03-linux-network-discovery
revision: 1
activity_at: "2026-11-03T12:50:26Z"
title: System Network Connections Discovery - Linux
slug: 2026-11-linux-network-discovery
description: This brief details the detection of common Linux utilities that may be used to enumerate active network connections, open ports, and listening services.
date: "2026-11-03T12:50:26Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1049/T1049.md
  - https://man7.org/linux/man-pages/man8/netstat.8.html
  - https://man7.org/linux/man-pages/man8/ss.8.html
  - https://man7.org/linux/man-pages/man8/lsof.8.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_system_network_connections_discovery.yml
rules:
  - title: System Network Connections Discovery - Linux
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1049
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Adversaries may use tools such as netstat, ss, lsof, or sockstat to enumerate active connections, open ports, and listening services on a compromised system. 

Legitimate administration activities may also utilize these utilities, which can result in false positives.
