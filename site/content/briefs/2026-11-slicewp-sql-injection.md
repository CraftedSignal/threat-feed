---
brief_id: brief-2026-11-07-slicewp-sql-injection
event_id: brief-2026-11-07-slicewp-sql-injection
revision: 1
activity_at: "2026-11-07T05:59:49Z"
title: 'SliceWP Affiliates: SQL injection in email parameter (CVE-2026-120043)'
slug: 2026-11-slicewp-sql-injection
description: An unauthenticated SQL injection vulnerability in SliceWP Affiliates versions 1.2.14 and earlier allows remote attackers to extract sensitive database information via the email parameter during WooCommerce registration.
date: "2026-11-07T05:59:49Z"
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
  - cpe:2.3:a:slicewp:slicewp_affiliates:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - sql-injection
  - web-application
  - cve-2026-120043
vendors:
  - SliceWP
products:
  - SliceWP Affiliates (<= 1.2.14)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The injection is reachable without any account because the vulnerable code path is triggered via the user_register hook fired on every successful WooCommerce My Account registration
    confidence_band: high
cves:
  - id: CVE-2026-120043
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120043
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade SliceWP Affiliates plugin to the latest patched version
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects versions up to and including 1.2.14
  hunt_leads:
    - lead: Monitor web access logs for suspicious input in WooCommerce registration requests
      technique_id: T1190
      data_needed:
        - Web server access logs capturing HTTP POST requests to registration endpoints
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is triggered via the user_register hook during WooCommerce My Account registration
  mitigation_plan:
    - priority: immediate
      action: Upgrade SliceWP Affiliates to version > 1.2.14
      owner: IT Operations
      addresses: CVE-2026-120043
      evidence: Plugin is vulnerable in all versions up to and including 1.2.14
---

CVE-2026-120043 is a SQL injection vulnerability within the SliceWP Affiliates plugin for WordPress. The flaw exists in the handling of the 'email' parameter due to insufficient input escaping and lack of parameterized queries. The vulnerability is reachable without authentication via the 'user_register' hook, which is triggered during WooCommerce user account creation. Successful exploitation allows an attacker to append arbitrary SQL queries to the backend database, potentially resulting in unauthorized data access.

## Impact

Unauthenticated remote attackers can perform arbitrary SQL queries against the underlying WordPress database, leading to the potential exposure of sensitive application data.

## Recommendation

- Upgrade the SliceWP Affiliates plugin to a version released after 1.2.14 that includes the fix for CVE-2026-120043.
- Until patching is possible, monitor WooCommerce registration traffic for anomalous 'email' parameter values containing SQL control characters or keywords.
- Audit database access logs for queries originating from the application layer that deviate from the expected baseline, particularly those involving unexpected UNION or OR statements.
