---
title: SQL Injection in Magistrala HTTP API
slug: 2026-09-magistrala-sqli
description: Magistrala versions prior to 1.0.0 contain a SQL injection vulnerability in the timescale-reader and postgres-reader services allowing authenticated users to achieve remote code execution via arbitrary SQL execution.
date: "2026-09-14T21:35:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:magistrala:magistrala:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - rce
vendors:
  - Magistrala
products:
  - Magistrala (< 1.0.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers with a self-registered account can substitute arbitrary subqueries to achieve... all injected SQL executing at superuser privilege.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1505.002
    technique_name: 'Server Software Component: Transport Agent'
    evidence: execute arbitrary code as the postgres OS user by loading attacker-supplied shared objects
    confidence_band: high
cves:
  - id: CVE-2026-82028
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82028
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Magistrala to version 1.0.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source states Magistrala before 1.0.0 contains a SQL injection vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade Magistrala to 1.0.0 or later
      owner: IT Operations
      addresses: CVE-2026-82028
      evidence: NVD vulnerability disclosure
---

Magistrala versions prior to 1.0.0 contain a critical SQL injection vulnerability residing within the timescale-reader and postgres-reader HTTP API services. The vulnerability stems from improper handling of the format query parameter, which is interpolated directly into the SQL FROM clause without parameterization or identifier quoting. An authenticated attacker, including those with self-registered accounts, can manipulate this parameter to inject arbitrary subqueries. Because the application connects to the underlying PostgreSQL database with superuser privileges, successful exploitation allows an attacker to perform cross-tenant data exfiltration, extract sensitive credentials such as pg_shadow hashes, read or write arbitrary files on the filesystem, and execute arbitrary system commands by loading attacker-supplied shared objects. This vulnerability represents a significant risk as it grants an authenticated user full control over the database and the underlying operating system user hosting the PostgreSQL process.

## Impact

Successful exploitation of CVE-2026-82028 allows for complete compromise of the Magistrala application data and the hosting server environment. Attackers can gain unauthorized access to data across all tenants, steal administrative credentials, and achieve remote code execution (RCE) with the privileges of the postgres OS user, leading to a full host takeover.

## Recommendation

1. Upgrade Magistrala to version 1.0.0 or later immediately to patch the vulnerable API services.
2. Audit database access logs for unusual SQL queries involving the timescale-reader or postgres-reader endpoints that utilize unexpected subqueries or attempts to access pg_shadow.
3. Restrict the privileges of the PostgreSQL service account to adhere to the principle of least privilege, preventing the application from executing commands or file operations at the OS level.
