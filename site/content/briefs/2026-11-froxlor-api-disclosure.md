---
brief_id: brief-2026-11-03-froxlor-api-disclosure
event_id: brief-2026-11-03-froxlor-api-disclosure
revision: 1
activity_at: "2026-11-03T16:00:11Z"
title: 'Froxlor: Information disclosure in api_keys.php (CVE-2026-121436)'
slug: 2026-11-froxlor-api-disclosure
description: Froxlor versions 2.3.8 through 2.3.14 are vulnerable to an information disclosure in api_keys.php that allows an administrator with customers_see_all privileges to retrieve API keys and secrets via an unscoped database query.
date: "2026-11-03T16:00:11Z"
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
  - cpe:2.3:a:froxlor:froxlor:2.3.8:*:*:*:*:*:*:*
tags:
  - webserver
  - vulnerability
  - privilege-escalation
vendors:
  - Froxlor
products:
  - Froxlor (2.3.8 <= version < 2.3.15)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552.001
    technique_name: Credentials In Files
    evidence: Attackers can read the super administrator's apikey and secret from the detail modal and replay them to the API to gain super administrator control.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Froxlor from 2.3.8 before 2.3.15 contains an information disclosure vulnerability that allows administrators with customers_see_all to view every account's API key and secret.
    confidence_band: high
cves:
  - id: CVE-2026-121436
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121436
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade Froxlor to version 2.3.15
      owner: IT Operations
      due: 48h
      evidence: Froxlor from 2.3.8 before 2.3.15 contains an information disclosure vulnerability
  hunt_leads:
    - lead: Identify access patterns to api_keys.php by users with customers_see_all privileges
      technique_id: T1552.001
      data_needed:
        - Web server access logs (cs-uri-stem, cs-username, sc-status)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: administrators with customers_see_all to view every account's API key and secret through an unscoped WHERE 1 query in api_keys.php
  mitigation_plan:
    - priority: immediate
      action: Restrict customers_see_all permission
      owner: IT Operations
      addresses: CVE-2026-121436
      evidence: vulnerability allows administrators with customers_see_all to view every account's API key
---

Froxlor versions 2.3.8 through 2.3.14 contain an information disclosure vulnerability in the api_keys.php component. An administrator assigned the 'customers_see_all' permission can view the API keys and secrets of all accounts, including the super administrator, due to an improperly scoped database query. Successful exploitation allows an attacker to gain unauthorized control of the platform via API replay attacks. 

## Impact
Unauthorized access to API keys and secrets enables privilege escalation to super administrator level, resulting in complete control over the Froxlor instance and associated account data.

## Recommendation
- Upgrade Froxlor to version 2.3.15 or later immediately.
- Review all API key access logs for suspicious or unauthorized usage by accounts with 'customers_see_all' privileges until the patch is applied.
- Implement restrictive access controls for the 'customers_see_all' permission while the application remains unpatched.
