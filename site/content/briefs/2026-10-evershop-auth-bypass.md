---
brief_id: brief-2026-10-22-evershop-auth-bypass
event_id: brief-2026-10-22-evershop-auth-bypass
revision: 1
activity_at: "2026-10-22T14:16:41Z"
title: 'EverShop: Missing authorization in customer address API (CVE-2026-115323)'
slug: 2026-10-evershop-auth-bypass
description: EverShop versions prior to 2.2.1 contain a missing authorization vulnerability in the customer address API, allowing unauthenticated attackers to manipulate other users' shipping addresses if the customer and address UUIDs are known.
date: "2026-10-22T14:16:41Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:evershop:evershop:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - api-security
vendors:
  - EverShop
products:
  - EverShop (< 2.2.1)
cves:
  - id: CVE-2026-115323
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115323
rules:
  - title: Detect CVE-2026-115323 Exploitation - Unauthorized Address API Modification
    description: Detects potential exploitation of CVE-2026-115323 by identifying POST, PATCH, or DELETE requests to the customer address API path
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch EverShop to version 2.2.1
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-115323 requires upgrade to 2.2.1 for remediation
  mitigation_plan:
    - priority: immediate
      action: Upgrade EverShop to version 2.2.1
      owner: IT Operations
      addresses: CVE-2026-115323
      evidence: Source NVD advisory for CVE-2026-115323
---

EverShop 1.2.2 through 2.2.0 contain a missing authorization vulnerability in the customer address API (CVE-2026-115323). This flaw allows unauthenticated attackers who possess knowledge of specific customer and address UUIDs to perform unauthorized POST, PATCH, or DELETE operations on the `/api/customers/:customer_id/addresses` routes. Exploitation could lead to unauthorized modification or removal of customer shipping data.

## Impact
Successful exploitation allows for the unauthorized modification, addition, or deletion of shipping addresses associated with any EverShop customer account, provided the attacker has obtained the necessary UUID identifiers.

## Recommendation
- Upgrade to EverShop 2.2.1 or later immediately to resolve the missing authorization flaw.
- Audit API logs for unauthorized `POST`, `PATCH`, or `DELETE` requests targeting `/api/customers/` endpoints that originate from unauthenticated sessions or atypical IP addresses.
- Monitor for high volumes of API requests targeting address UUIDs to identify potential enumeration or bulk modification attempts.
