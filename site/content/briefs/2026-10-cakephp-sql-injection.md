---
brief_id: brief-2026-10-30-cakephp-sql-injection
event_id: brief-2026-10-30-cakephp-sql-injection
revision: 1
activity_at: "2026-10-30T13:29:14Z"
title: 'CakePHP: SQL injection in WindowExpression (CVE-2026-119418)'
slug: 2026-10-cakephp-sql-injection
description: CakePHP versions through 5.4.3 contain an SQL injection vulnerability in the WindowExpression::range() and frame() methods that allows attackers to execute arbitrary SQL via crafted input passed to the OVER clause.
date: "2026-10-30T13:29:14Z"
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
  validation_status: Needs environment verification of affected codebase
cpes:
  - cpe:2.3:a:cakephp:cakephp:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - web-framework
vendors:
  - CakePHP
products:
  - CakePHP (<= 5.4.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CakePHP through 5.4.3 contains an sql injection vulnerability that allows attackers to inject SQL by supplying unvalidated frame offsets and directions
    confidence_band: high
cves:
  - id: CVE-2026-119418
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119418
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Identify CakePHP implementations <= 5.4.3 and prepare for update
      owner: IT Operations
      due: 48h
      evidence: Vulnerability in CakePHP 5.4.3 and lower
  hunt_leads:
    - lead: Search application logs for SQL injection patterns involving OVER clauses or unexpected characters in windowing function parameters
      technique_id: T1190
      data_needed:
        - Application request logs
        - Database query logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can pass crafted values through applications forwarding user input into the OVER clause
  mitigation_plan:
    - priority: immediate
      action: Upgrade CakePHP to a patched version once released
      owner: IT Operations
      addresses: CVE-2026-119418
      evidence: CakePHP through 5.4.3 contains an sql injection vulnerability
---

CakePHP versions through 5.4.3 contain an SQL injection vulnerability arising from the improper validation of frame offsets and directions within the `WindowExpression::range()` and `frame()` methods. Applications that pass user-supplied input into these methods, which are subsequently rendered in the `OVER` clause of a SQL query, are susceptible to exploitation. An attacker can leverage this flaw to execute unauthorized SQL statements using the privileges of the database connection.

## Impact

Successful exploitation allows for unauthorized SQL execution, which can lead to data exfiltration, database modification, or denial of service depending on the application database configuration and privileges.

## Recommendation

- Inventory all applications utilizing CakePHP versions 5.4.3 or older.
- Review custom code for any usage of `WindowExpression::range()` or `frame()` that incorporates untrusted user input.
- Apply patches or upgrade to a version of CakePHP that addresses this vulnerability once available.
- Implement strict input validation and sanitization for all parameters passed to framework query building methods.
