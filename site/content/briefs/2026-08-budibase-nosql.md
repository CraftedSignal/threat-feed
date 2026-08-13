---
title: NoSQL Injection in Budibase Server
slug: 2026-08-budibase-nosql
description: Budibase Server versions before 3.40.0 contain a NoSQL injection vulnerability in the MongoDB query execution endpoint, enabling authenticated attackers to bypass filters and perform unauthorized database operations.
date: "2026-08-13T12:57:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - nosql-injection
  - database-security
vendors:
  - Budibase
products:
  - Budibase Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Budibase Server before 3.40.0 contains a NoSQL injection vulnerability in the MongoDB query execution endpoint where user-supplied parameters are interpolated into JSON query templates without proper sanitization.
    confidence_band: high
cves:
  - id: CVE-2026-73618
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73618
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Budibase Server to 3.40.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-73618 advisory
  mitigation_plan:
    - priority: immediate
      action: Upgrade software to version 3.40.0
      owner: IT Operations
      addresses: CVE-2026-73618
      evidence: NVD advisory
---

Budibase Server versions prior to 3.40.0 contain a critical NoSQL injection vulnerability within the MongoDB query execution component. The flaw arises from improper sanitization of user-supplied parameters that are interpolated into JSON query templates. An attacker with query write permissions can inject malicious JSON structural characters, such as curly braces or operator keys (e.g., $gt, $ne), to manipulate the underlying database queries. By subverting these query structures, an adversary can bypass application-level access controls to perform unauthorized operations, including reading sensitive records, modifying existing documents, or deleting data from the database. This vulnerability poses a significant risk to data integrity and confidentiality for deployments of Budibase Server versions below 3.40.0.

## Impact

Successful exploitation allows authenticated attackers with standard query write privileges to escalate their access to sensitive database contents. This can lead to full data exfiltration, unauthorized modification of application state, or destructive database operations, impacting the overall security of the Budibase instance and any business-critical data processed by the platform.

## Recommendation

* Upgrade Budibase Server to version 3.40.0 or later immediately to apply the vendor-provided sanitization fix for MongoDB query templates.
* Audit access control logs to identify accounts with query write permissions that have exhibited unusual request patterns or attempted injection of JSON operators.
* Monitor database access logs for high volumes of document modification or deletion commands emanating from the Budibase application service account.
