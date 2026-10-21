---
brief_id: brief-2026-10-21-sourcecodester-food-order-management-system-auth-bypass
event_id: brief-2026-10-21-sourcecodester-food-order-management-system-auth-bypass
revision: 1
activity_at: "2026-10-21T19:58:02Z"
title: 'SourceCodester Food Order Management System: Missing Authorization in Admin Endpoint (CVE-2026-114267)'
slug: 2026-10-sourcecodester-food-order-management-system-auth-bypass
description: CVE-2026-114267 affects SourceCodester Food Order Management System 1.0, where an unknown function in the Admin Endpoint component exhibits missing authorization.
date: "2026-10-21T19:58:02Z"
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
  - cpe:2.3:a:sourcecodester:food_order_management_system:*:*:*:*:*:*:*:*
vendors:
  - SourceCodester
products:
  - Food Order Management System (1.0)
cves:
  - id: CVE-2026-114267
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114267
---

A vulnerability has been identified in SourceCodester Food Order Management System 1.0. The vulnerability involves missing authorization within an unknown function of the Admin Endpoint component. The attack can be performed remotely, and public exploit code is available.
