---
title: SQL Injection in WebVella ERP EQL API
slug: 2026-10-webvella-sql-injection
description: Authenticated users can exploit an SQL injection vulnerability in the WebVella ERP EQL query API to exfiltrate sensitive data from user and role tables.
date: "2026-10-16T18:50:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:webvella:erp:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
  - erp
vendors:
  - WebVella
products:
  - WebVella ERP (<= 1.8.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: WebVella ERP through 1.8.8 contains an sql injection vulnerability that allows any authenticated user to inject SQL through WHERE-clause text literals in the EQL query API.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can send crafted single-quoted literals to POST /api/v3/en_US/eql... to read unauthorized entities, including user and role tables.
    confidence_band: high
cves:
  - id: CVE-2026-111700
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111700
rules:
  - title: Detect CVE-2026-111700 Exploitation - SQL Injection in EQL API
    description: Detects exploitation attempts against the WebVella ERP EQL API by searching for SQL-injected payloads containing single quotes in the request body.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review logs for suspicious POST requests to /api/v3/en_US/eql
      owner: SOC
      due: 24h
      evidence: Source documentation of the vulnerable API endpoint.
  mitigation_plan:
    - priority: immediate
      action: Upgrade WebVella ERP when patch version > 1.8.8 is released.
      owner: IT Operations
      addresses: CVE-2026-111700
      evidence: NVD advisory for CVE-2026-111700.
---

WebVella ERP, in all versions up to and including 1.8.8, contains a critical SQL injection vulnerability within its EQL (Entity Query Language) query API. The flaw stems from improper sanitization of WHERE-clause text literals when processing requests to the EQL engine. An authenticated attacker can supply crafted input containing single-quoted literals via the POST /api/v3/en_US/eql endpoint to break out of the intended query structure. By manipulating the EqlBuilder SQL interpolation, the attacker can execute arbitrary SQL commands against the backend database. This vulnerability poses a significant risk to organizational confidentiality, as it allows unauthorized access to sensitive database entities, specifically including user and role information which could be leveraged for further privilege escalation or total system compromise.

## Impact

Successful exploitation allows an authenticated user to perform unauthorized database queries, leading to the potential exfiltration of sensitive organizational data. Targeting of the user and role tables enables attackers to gain administrative credentials or escalate privileges within the ERP application, directly impacting data integrity and confidentiality.

## Recommendation

- Upgrade WebVella ERP to a version beyond 1.8.8 as soon as a security patch is provided by the vendor.
- Implement strict input validation and parameterized queries for the EqlBuilder component to prevent raw SQL injection.
- Monitor logs for the /api/v3/en_US/eql endpoint, specifically looking for POST requests containing high frequencies of single-quote characters or unusual SQL syntax patterns within the request body.
- Restrict access to the /api/v3/en_US/eql endpoint to only authorized service accounts and administrative users until a patch is applied.
