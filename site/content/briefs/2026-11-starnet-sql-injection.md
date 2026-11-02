---
brief_id: brief-2026-11-02-starnet-sql-injection
event_id: brief-2026-11-02-starnet-sql-injection
revision: 1
activity_at: "2026-11-02T15:48:14Z"
title: 'Starnet Inventory Tracking Application: SQL Injection (CVE-2026-74993)'
slug: 2026-11-starnet-sql-injection
description: An SQL injection vulnerability in the Starnet Computer and Network Systems Inventory Tracking Application allows SQL Injection.
date: "2026-11-02T15:48:14Z"
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
cpes:
  - cpe:2.3:a:starnet_computer_and_network_systems:inventory_tracking_application:*:*:*:*:*:*:*:*
vendors:
  - Starnet Computer and Network Systems
products:
  - Inventory Tracking Application (through 2026-10-16)
cves:
  - id: CVE-2026-74993
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74993
---

CVE-2026-74993 describes an improper neutralization of special elements used in an SQL command (SQL injection) vulnerability in the Starnet Computer and Network Systems Inventory Tracking Application. This issue affects the Inventory Tracking Application in all versions through 2026-10-16.

## Impact
The vulnerability allows SQL Injection.
