---
brief_id: brief-2026-10-23-basercms-sqli
event_id: brief-2026-10-23-basercms-sqli
revision: 1
activity_at: "2026-10-23T15:07:45Z"
title: 'baserCMS: SQL injection in administrative prefixes (CVE-2026-114621)'
slug: 2026-10-basercms-sqli
description: baserCMS versions 5.0.0 through 5.3.1 and 5.4.0 through 5.4.1 contain an SQL injection vulnerability in the Admin and Api/Admin interfaces allowing authenticated users to execute arbitrary SQL queries.
date: "2026-10-23T15:07:45Z"
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
  validation_status: Source-confirmed vulnerability details.
cpes:
  - cpe:2.3:a:basercms:basercms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sqli
  - authentication
vendors:
  - baserCMS
products:
  - baserCMS (5.0.0 through 5.3.1, 5.4.0 through 5.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker with access to the admin panel can embed SQL fragments in those options to execute arbitrary SQL against the application database.
    confidence_band: high
cves:
  - id: CVE-2026-114621
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114621
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade baserCMS to 5.3.2 or 5.4.2
      owner: IT Operations
      due: 24h
      evidence: This issue has been patched in versions 5.3.2 and 5.4.2.
  hunt_leads:
    - lead: Inspect web server logs for requests to /admin/ or /api/admin/ endpoints containing suspicious query parameters
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability allows injection via query parameters including contain, conditions, fields, finder, and order.
  mitigation_plan:
    - priority: immediate
      action: Upgrade baserCMS to versions 5.3.2 or 5.4.2
      owner: IT Operations
      addresses: CVE-2026-114621
      evidence: This issue has been patched in versions 5.3.2 and 5.4.2.
---

baserCMS versions 5.0.0 through 5.3.1 and 5.4.0 through 5.4.1 are susceptible to SQL injection via the Admin and Api/Admin prefixes. The vulnerability stems from the framework passing request query parameters (specifically contain, conditions, fields, finder, and order) directly to the ORM without sufficient validation. An authenticated attacker can embed SQL fragments within these parameters to manipulate database queries, potentially leading to unauthorized data extraction, such as password hashes. Disabling the core admin API does not mitigate this risk for users with active admin sessions. This issue is resolved in versions 5.3.2 and 5.4.2.

## Impact

Successful exploitation allows an authenticated attacker with access to the administrative panel to perform arbitrary SQL operations against the underlying application database.

## Recommendation

- Upgrade baserCMS instances to versions 5.3.2 or 5.4.2 immediately to remediate the ORM parameter validation flaw.
- Audit administrative session logs for unusual patterns or high-volume query parameter usage consistent with SQL injection payloads.
- Restrict access to administrative and API prefixes at the network or web application firewall level to trusted internal sources only.
