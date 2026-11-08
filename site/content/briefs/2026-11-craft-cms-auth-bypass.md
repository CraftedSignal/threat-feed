---
brief_id: brief-2026-11-08-craft-cms-auth-bypass
event_id: brief-2026-11-08-craft-cms-auth-bypass
revision: 1
activity_at: "2026-11-08T15:28:35Z"
title: 'Craft CMS: Authorization bypass via GraphQL API (CVE-2026-124427)'
slug: 2026-11-craft-cms-auth-bypass
description: Craft CMS versions 5.0.0 through 5.11.1 contain an authorization bypass vulnerability allowing unauthenticated GraphQL clients to enumerate and extract out-of-scope content.
date: "2026-11-08T15:28:35Z"
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
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
vendors:
  - Craft CMS
products:
  - Craft CMS (5.0.0 through 5.11.1)
cves:
  - id: CVE-2026-124427
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124427
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Craft CMS to 5.11.2 or later
      owner: IT Operations
      due: 24h
      evidence: Source notes version 5.11.2 contains the fix for the authorization bypass
  hunt_leads:
    - lead: Identify anomalous GraphQL activity or high-volume traversal via prev/next queries
      technique_id: T1592
      data_needed:
        - Web server access logs
        - GraphQL API audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers chain next hops from one visible in-scope entry to enumerate entries
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected Craft CMS installations to 5.11.2
      owner: IT Operations
      addresses: CVE-2026-124427
      evidence: NVD advisory for CVE-2026-124427
---

Craft CMS versions 5.0.0 before 5.11.2 are affected by an authorization bypass vulnerability in the GraphQL API. The flaw allows unauthenticated attackers to access entries that should be withheld by traversing the prev/next navigation fields. By chaining these queries, attackers can enumerate and extract data from private or out-of-scope sections, including titles, slugs, and custom field content.

## Impact
Unauthorized exposure of sensitive data stored in Craft CMS sections. Potential for full information disclosure of private entries.

## Recommendation
Upgrade Craft CMS to version 5.11.2 or later immediately to resolve the authorization logic flaw.
