---
title: NoSQL Injection Vulnerability in Budibase MongoDB Integration
slug: 2026-08-budibase-nosql-injection
description: Budibase versions prior to 3.40.0 are vulnerable to NoSQL injection in the MongoDB datasource due to improper handling of user-supplied parameters, allowing unauthorized data access and potential server-side execution.
date: "2026-08-13T12:56:46Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Budibase
products:
  - Budibase
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: 'Budibase before 3.40.0 contains a NoSQL injection vulnerability in the MongoDB datasource integration where user-supplied parameters are enriched with handlebars using noEscaping: true and parsed without operator filtering.'
    confidence_band: high
cves:
  - id: CVE-2026-73617
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73617
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Budibase to version 3.40.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-73617 vendor patch release
  mitigation_plan:
    - priority: immediate
      action: Review MongoDB service account permissions used by Budibase
      owner: IT Operations
      addresses: CVE-2026-73617
      evidence: NoSQL injection allows modification or deletion of collection data
---

Budibase versions prior to 3.40.0 contain a critical NoSQL injection vulnerability within the MongoDB datasource integration. The vulnerability stems from the application's processing of user-supplied parameters using Handlebars with the 'noEscaping: true' setting enabled, combined with a lack of robust operator filtering. 

This flaw allows an attacker to inject MongoDB-specific operators directly into query parameters. Because the input is not sanitized or restricted, an attacker can manipulate database queries to bypass existing row-level or per-user access controls. The impact is severe, enabling unauthorized read access to arbitrary documents, potential modification or deletion of collection data, and the execution of server-side JavaScript through operators such as '$where'. This vulnerability is particularly dangerous in environments where the Budibase backend connects to MongoDB databases containing sensitive business logic or user data.

## Impact

Successful exploitation allows attackers to bypass application-level access controls, leading to unauthorized data exfiltration or modification. In instances where the MongoDB instance allows the '$where' operator, attackers could escalate the impact to arbitrary code execution on the database server. This impacts all organizations using Budibase 3.39.x and earlier versions that integrate with MongoDB.

## Recommendation

* Upgrade Budibase instances to version 3.40.0 or later immediately to patch CVE-2026-73617.
* Audit logs for suspicious MongoDB queries involving unconventional operators (e.g., $where, $gt, $ne, $regex) originating from the Budibase application server.
* Implement strict input validation and query parameterization for any user-facing inputs bound to MongoDB datasource queries.
* Apply the principle of least privilege to the service account credentials used by Budibase to connect to MongoDB, restricting permissions to only those necessary for required operations.
