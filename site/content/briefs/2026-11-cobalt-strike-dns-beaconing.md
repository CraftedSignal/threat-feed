---
brief_id: brief-2026-11-10-cobalt-strike-dns-beaconing
event_id: brief-2026-11-10-cobalt-strike-dns-beaconing
revision: 1
activity_at: "2026-11-10T03:38:18Z"
title: Cobalt Strike DNS Beaconing Patterns
slug: 2026-11-cobalt-strike-dns-beaconing
description: Detection of suspicious DNS query patterns associated with Cobalt Strike command and control communication.
date: "2026-11-10T03:38:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - cobalt-strike
  - command-and-control
  - dns-tunneling
references:
  - https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
  - https://web.archive.org/web/20211022162145/https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_mal_cobaltstrike.yml
rules:
  - title: Detect Suspicious Cobalt Strike DNS Beaconing
    description: Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons.
    platform: sigma
    severity: critical
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - dns_query
      - windows
rules_count: 1
---

This brief identifies specific DNS query naming conventions associated with Cobalt Strike beacons. Detection is based on Sysmon DNS query logging.

## Detection Logic

The detection identifies programs invoking DNS queries with the following naming patterns:
- Queries starting with "aaa.stage." or "post.1"
- Queries containing ".stage.123456."
