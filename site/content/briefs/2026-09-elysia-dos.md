---
title: Denial of Service in Elysia via Algorithmic Complexity
slug: 2026-09-elysia-dos
description: Elysia versions before 1.4.29 are vulnerable to a denial-of-service attack due to quadratic time complexity in the 'multipart/form-data' normalization process, leading to CPU exhaustion.
date: "2026-09-24T01:57:02Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:elysiajs:elysia:*:*:*:*:*:node.js:*:*
tags:
  - denial-of-service
  - vulnerability
  - web-framework
vendors:
  - Elysia
products:
  - Elysia (< 1.4.29)
cves:
  - id: CVE-2026-56669
    cvss: 7.5
    epss: 0.0063
references:
  - https://github.com/advisories/GHSA-9643-4qgh-g8mx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56669
action_plan:
  priority: elevated
  owners:
    - Engineering
    - SOC
  immediate_actions:
    - action: Upgrade Elysia package to 1.4.29
      owner: Engineering
      due: 48h
      evidence: Source states patch is 1.4.29
  mitigation_plan:
    - priority: immediate
      action: Monitor server CPU utilization for endpoints processing multipart/form-data
      owner: SOC
      addresses: CVE-2026-56669
      evidence: Source describes CPU exhaustion vulnerability
---

Elysia versions prior to 1.4.29 contain an algorithmic complexity vulnerability (CVE-2026-56669) within the framework's `multipart/form-data` normalization logic. When the framework processes incoming form data, the internal `getAll` method used to retrieve values operates with quadratic time complexity relative to the number of key-value pairs provided. Specifically, for each unique key in the form data, the normalization process scans all existing key-value pairs. Consequently, an attacker can craft a malicious multipart request containing a large number of unique keys, forcing the application to perform n-squared operations. This results in significant CPU consumption, potentially leading to a denial-of-service state for the affected application endpoint. The issue is resolved in version 1.4.29, which optimizes the data retrieval process to prevent the identified CPU exhaustion.

## Impact

The vulnerability directly impacts web applications and API endpoints built using the Elysia framework that accept `multipart/form-data` uploads. Successful exploitation allows an unauthenticated attacker to cause excessive CPU utilization on the server, potentially rendering the service unresponsive to legitimate users.

## Recommendation

Prioritized actions for development and security engineering teams:

- Upgrade the Elysia dependency to version 1.4.29 or later immediately to incorporate the algorithmic fix for CVE-2026-56669.
- Audit existing infrastructure to identify internet-facing endpoints processing multipart form data.
- Implement request size and complexity limits at the web application firewall (WAF) or load balancer level to mitigate potential resource exhaustion attacks while the patching process is completed.
