---
title: SQL Injection Vulnerability in CakePHP FunctionsBuilder
slug: 2026-09-cakephp-sql-injection
description: Multiple methods in the CakePHP FunctionsBuilder component are vulnerable to SQL injection when user-supplied input is passed to specific functional parameters.
date: "2026-09-18T01:10:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - CakePHP
products:
  - cakephp/database (< 4.5.12, >= 4.6.0 < 4.6.5, >= 5.0.0 < 5.1.9, >= 5.2.0 < 5.2.14, >= 5.3.0 < 5.3.7)
  - cakephp/cakephp (< 4.5.12, >= 4.6.0 < 4.6.5, >= 5.0.0 < 5.1.9, >= 5.2.0 < 5.2.14, >= 5.3.0 < 5.3.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The functions are vulnerable to SQL injection if user controlled data is supplied to the ($dataType / $part / $unit) parameters.
    confidence_band: high
cves:
  - id: CVE-2026-79752
references:
  - https://github.com/advisories/GHSA-vjqc-q4mp-2rvf
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-79752
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade cakephp/database and cakephp/cakephp to 5.3.7, 5.2.14, 5.1.9, 4.6.5, or 4.5.12.
      owner: IT Operations
      addresses: CVE-2026-79752
      evidence: 5.3.7, 5.2.14, 5.1.9, 4.6.5, 4.5.12 contain fixes
---

The CakePHP framework contains a critical SQL injection vulnerability (CVE-2026-79752) affecting the `FunctionsBuilder` component. The vulnerability exists in the `cast($field, $dataType)`, `extract($part, $expr)`, `datePart($part, $expr)`, and `dateAdd($expr, $value, $unit)` methods. An attacker can exploit this flaw by supplying malicious user-controlled input to the `$dataType`, `$part`, or `$unit` parameters of these functions. If an application fails to sanitize or validate input before passing it to these parameters, an attacker can manipulate the resulting SQL query, potentially leading to unauthorized database access, data exfiltration, or modification. This issue impacts multiple versions of the `cakephp/database` and `cakephp/cakephp` packages across the 4.x and 5.x branches. Organizations using these versions are encouraged to update to the patched releases immediately.

## Impact

Successful exploitation of this vulnerability allows unauthenticated or authenticated attackers to execute arbitrary SQL commands against the database used by the CakePHP application. The impact includes the potential for full database compromise, unauthorized disclosure of sensitive information, and loss of data integrity. All applications leveraging the vulnerable `FunctionsBuilder` methods with dynamic user input are at risk, regardless of the sector.

## Recommendation

- Upgrade the `cakephp/database` and `cakephp/cakephp` packages to the versions containing the security fix: 5.3.7, 5.2.14, 5.1.9, 4.6.5, or 4.5.12.
- Audit existing application code to identify any instances where user-supplied data is passed directly into `FunctionsBuilder` methods without strict validation or allowlisting.
- Implement a temporary workaround by ensuring that all user-supplied data passed to `cast`, `extract`, `datePart`, and `dateAdd` parameters is hardcoded or strictly filtered against a known-safe list of values before function invocation.
