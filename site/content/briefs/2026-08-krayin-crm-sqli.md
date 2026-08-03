---
title: Blind SQL Injection in Krayin CRM leads DataGrid
slug: 2026-08-krayin-crm-sqli
description: Krayin CRM versions prior to 2.2.4 contain a blind SQL injection vulnerability in the leads DataGrid, allowing authenticated attackers to exfiltrate database contents via the rotten_lead[in] query parameter.
date: "2026-08-03T18:06:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
vendors:
  - Krayin
products:
  - Krayin CRM (< 2.2.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Krayin CRM before 2.2.4 contains a blind SQL injection vulnerability in the leads DataGrid that allows authenticated users with leads access to inject arbitrary SQL
    confidence_band: high
cves:
  - id: CVE-2026-41453
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41453
rules:
  - title: Detects CVE-2026-41453 Exploitation - Blind SQL Injection in leads DataGrid
    description: Detects potential SQL injection attempts against the Krayin CRM leads DataGrid via the rotten_lead parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Krayin CRM to version 2.2.4
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-41453 official patch version
  mitigation_plan:
    - priority: immediate
      action: Restrict access to CRM leads module
      owner: IT Operations
      addresses: CVE-2026-41453
      evidence: Vulnerability restricted to leads DataGrid
---

Krayin CRM versions prior to 2.2.4 are vulnerable to a blind SQL injection vulnerability within the leads DataGrid component. The vulnerability arises because the application fails to properly sanitize or parameterize input provided to the 'rotten_lead[in]' query parameter before passing it to a 'havingRaw()' call in 'LeadDataGrid.php'. An authenticated user with sufficient permissions to access the leads module can leverage this flaw to inject arbitrary SQL statements. By employing time-based or boolean-based blind injection techniques, an attacker can systematically extract sensitive information from the underlying database, including user credential hashes, CRM contact records, and application configuration metadata. This vulnerability poses a significant risk to the confidentiality of data stored within the CRM.

## Impact

Successful exploitation allows an authenticated attacker to perform unauthorized database queries, leading to full exfiltration of CRM data, user credentials, and application secrets. This impact is rated with a CVSS v3.1 base score of 8.8, indicating high potential for data breach and compromise of organizational intelligence contained within the CRM.

## Recommendation

* Upgrade all Krayin CRM instances to version 2.2.4 or later immediately to patch CVE-2026-41453.
* Audit application access logs for unusual patterns in the 'rotten_lead[in]' parameter, particularly involving SQL keywords such as 'SLEEP', 'BENCHMARK', 'AND', 'OR', or 'UNION'.
* Restrict access to the leads DataGrid module to a strictly defined subset of users until the patch can be applied.
