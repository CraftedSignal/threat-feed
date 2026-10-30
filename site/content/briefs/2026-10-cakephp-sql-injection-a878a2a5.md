---
brief_id: brief-2026-10-30-cakephp-sql-injection-a878a2a5
event_id: brief-2026-10-30-cakephp-sql-injection-a878a2a5
revision: 1
activity_at: "2026-10-30T13:29:22Z"
title: 'CakePHP: SQL injection in StringExpression and IdentifierExpression (CVE-2026-119419)'
slug: 2026-10-cakephp-sql-injection-a878a2a5
description: CakePHP through version 5.4.3 contains an SQL injection vulnerability in its query building components that allows unvalidated collation values to trigger arbitrary SQL execution.
date: "2026-10-30T13:29:22Z"
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
  - cpe:2.3:a:cakephp:cakephp:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - sqli
  - cakephp
vendors:
  - Cake Software Foundation
products:
  - CakePHP (<= 5.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CakePHP through 5.4.3 contains an sql injection vulnerability that allows attackers to inject SQL by supplying unvalidated collation values.
    confidence_band: high
cves:
  - id: CVE-2026-119419
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119419
action_plan:
  priority: elevated
  owners:
    - SOC
    - Development
  immediate_actions:
    - action: Inventory all application instances utilizing CakePHP 5.4.3 or earlier
      owner: SOC
      due: 24h
      evidence: Vulnerability affects CakePHP through 5.4.3
  hunt_leads:
    - lead: Identify database query logs or WAF logs containing SQL syntax in unexpected fields, specifically near COLLATE clauses
      technique_id: T1190
      data_needed:
        - Web application logs
        - Database query logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers... can append SQL after the unquoted COLLATE clause
  mitigation_plan:
    - priority: immediate
      action: Upgrade CakePHP to the latest patched version
      owner: Development
      addresses: CVE-2026-119419
      evidence: CakePHP through 5.4.3 contains an sql injection vulnerability
---

CakePHP versions 5.4.3 and earlier are susceptible to an SQL injection vulnerability. The flaw exists within the `StringExpression` and `IdentifierExpression` classes. Attackers who can control the collation parameter passed to the constructor or the `setCollation()` method can inject arbitrary SQL commands. The injected payload is appended after the unquoted `COLLATE` clause and executes with the privileges of the active database connection.

## Impact
Successful exploitation allows attackers to execute arbitrary SQL commands against the backend database, potentially resulting in unauthorized data access, modification, or destruction, depending on the privileges of the database user configured in the application.

## Recommendation
- Audit custom application code using CakePHP to identify instances where user-supplied input is passed to `StringExpression`, `IdentifierExpression`, or the `setCollation()` method.
- Implement strict input validation or allow-listing for any collation parameters processed by these methods.
- Upgrade to the latest version of CakePHP that includes the security patch for CVE-2026-119419 once available.
