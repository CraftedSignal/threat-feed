---
title: Unauthenticated Stacked SQL Injection in R2R
slug: 2026-09-r2r-sql-injection
description: R2R versions through 3.6.6 contain a stacked SQL injection vulnerability allowing unauthenticated attackers to execute arbitrary DDL and DML commands via the index name parameter.
date: "2026-09-03T19:22:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:r2r:r2r:*:*:*:*:*:*:*:*
vendors:
  - R2R
products:
  - R2R (<= 3.6.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: R2R through 3.6.6 contains a stacked SQL injection vulnerability that allows unauthenticated attackers to execute arbitrary SQL statements.
    confidence_band: high
cves:
  - id: CVE-2026-82526
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82526
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all instances of R2R to versions beyond 3.6.6.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82526 advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the vector index creation endpoint.
      owner: IT Operations
      addresses: CVE-2026-82526
      evidence: Unauthenticated attacker vector identified
---

R2R versions through 3.6.6 contain a high-severity stacked SQL injection vulnerability (CVE-2026-82526). The flaw resides in the vector index creation endpoint, where the 'index name' parameter is interpolated directly into a 'CREATE INDEX' statement. Due to a lack of identifier quoting and input validation, an unauthenticated attacker can inject arbitrary SQL commands. Because the application interacts with the backend database using a PostgreSQL superuser account, successful exploitation allows for unauthorized DDL and DML operations. This poses a significant risk to the integrity and confidentiality of the underlying database. Defenders should prioritize patching affected R2R instances to version 3.6.7 or later if available, or restrict access to the index creation API.

## Impact

Successful exploitation of this vulnerability permits full database compromise. Attackers can execute arbitrary SQL statements, potentially leading to data exfiltration, modification of system configurations, or administrative access to the underlying PostgreSQL instance. As this is an unauthenticated vector, it is accessible to any remote actor capable of reaching the R2R API.

## Recommendation

- Patch R2R instances to a version higher than 3.6.6 immediately.
- Implement strict input validation on the index name parameter to ensure it conforms to expected identifier patterns (e.g., alphanumeric only).
- Review database logs for unexpected DDL statements or queries originating from the R2R service account.
- Restrict network access to the R2R vector index creation API to authorized clients only via firewall or proxy rules.
