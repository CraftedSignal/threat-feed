---
brief_id: brief-2026-10-30-trilogy-sqli
event_id: brief-2026-10-30-trilogy-sqli
revision: 1
activity_at: "2026-10-30T21:20:14Z"
title: 'Trilogy: SQL Injection vulnerability via multibyte encodings'
slug: 2026-10-trilogy-sqli
description: A SQL injection vulnerability in the Trilogy library (versions prior to 2.13.2) allows unauthenticated attackers to execute arbitrary SQL via improperly escaped multibyte strings.
date: "2026-10-30T21:20:14Z"
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
  - cpe:2.3:a:trilogy_project:trilogy:*:*:*:*:*:*:*:*
products:
  - trilogy (< 2.13.2)
references:
  - https://discuss.rubyonrails.org/t/ghsa-744p-w4gc-m3gh-sql-injection-through-trilogy-escape-with-multibyte-encodings/91797
  - https://github.com/trilogy-libraries/trilogy/security/advisories/GHSA-744p-w4gc-m3gh
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1424/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Team
  immediate_actions:
    - action: Upgrade Trilogy dependency to 2.13.2 or later
      owner: Development Team
      due: 48h
      evidence: Vulnerability affects all versions prior to 2.13.2
  hunt_leads:
    - lead: Identify applications using Trilogy that accept multibyte input
      technique_id: T1190
      data_needed:
        - Software dependency manifest (Gemfile.lock)
        - Database query logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability involves improper handling of multibyte encodings
  mitigation_plan:
    - priority: immediate
      action: Apply security patch by updating Trilogy library to 2.13.2
      owner: IT Operations
      addresses: GHSA-744p-w4gc-m3gh
      evidence: Official fix provided by maintainers
---

A SQL injection vulnerability exists in the Trilogy library, an underlying database client used in some Ruby on Rails environments. The flaw stems from improper handling of multibyte character encodings during string escaping, which can allow an attacker to bypass protection mechanisms. Updating to version 2.13.2 or later is required to mitigate this vulnerability.

## Impact

Successful exploitation could lead to unauthorized database access, data exfiltration, or modification of application data depending on the implementation of the database queries and the application environment.

## Recommendation

- Upgrade the Trilogy library to version 2.13.2 or later in all projects utilizing the library as a database dependency.
- Audit database queries using user-supplied input to ensure that parameterized queries or safe ORM methods are used as a defense-in-depth measure.
- Review application logs for unusual query patterns or unexpected database errors that may indicate injection attempts.
