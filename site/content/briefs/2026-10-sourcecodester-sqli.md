---
brief_id: brief-2026-10-25-sourcecodester-sqli
event_id: brief-2026-10-25-sourcecodester-sqli
revision: 1
activity_at: "2026-10-25T20:30:02Z"
title: 'SourceCodester Performance Indicator System: SQL Injection in Contact argument (CVE-2026-116060)'
slug: 2026-10-sourcecodester-sqli
description: SourceCodester Performance Indicator System 1.0 contains an SQL injection vulnerability in the 'Contact' argument of '/opils/staff/adddealer.php', which can be triggered remotely.
date: "2026-10-25T20:30:02Z"
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
  - cpe:2.3:a:sourcecodester:performance_indicator_system:*:*:*:*:*:*:*:*
vendors:
  - SourceCodester
products:
  - Performance Indicator System (1.0)
cves:
  - id: CVE-2026-116060
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116060
---

A vulnerability has been identified in SourceCodester Performance Indicator System 1.0. The flaw exists in the '/opils/staff/adddealer.php' file. Manipulation of the 'Contact' argument can lead to SQL injection. The vulnerability can be exploited remotely, and the exploit has been publicly disclosed.
