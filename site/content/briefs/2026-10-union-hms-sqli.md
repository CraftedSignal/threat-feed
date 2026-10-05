---
title: SQL Injection in UNION HospitalManagementSystem
slug: 2026-10-union-hms-sqli
description: The UNION HospitalManagementSystem is vulnerable to remote SQL injection via the patient_id parameter in patient_info.php, allowing unauthenticated attackers to manipulate database queries.
date: "2026-10-05T18:48:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:union:hospitalmanagementsystem:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
  - remote-code-execution
vendors:
  - UNION
products:
  - HospitalManagementSystem (up to commit 9ef91ed6007314b6473110ed699dff76d158f61d)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Performing a manipulation of the argument patient_id results in sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-105384
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105384
rules:
  - title: Detects CVE-2026-105384 Exploitation - SQL Injection in HospitalManagementSystem
    description: Detects potential SQL injection attempts targeting the patient_id argument in patient_info.php.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF filtering for patient_info.php targeting patient_id parameter
      owner: SOC
      due: 24h
      evidence: Source confirms public exploit availability for CVE-2026-105384
  mitigation_plan:
    - priority: medium_term
      action: Monitor upstream repository for official patch or security release
      owner: IT Operations
      addresses: CVE-2026-105384
      evidence: Project has not responded to vulnerability report
---

A remote SQL injection vulnerability exists in the UNION HospitalManagementSystem, specifically within the patient_info.php script. The flaw is triggered by improper sanitization of the patient_id argument, which allows an unauthenticated remote attacker to inject malicious SQL commands into the backend database. This vulnerability affects all versions of the software up to commit 9ef91ed6007314b6473110ed699dff76d158f61d. Due to the project's use of a rolling release strategy, there is no specific version identifier for a patch; users are advised to monitor the upstream repository for updates. The vulnerability has been publicly disclosed with an associated exploit, increasing the risk of exploitation for organizations utilizing this software in their environment.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary SQL queries against the database supporting the HospitalManagementSystem. This could result in unauthorized access to, or exfiltration of, sensitive patient data, modification of database records, or potential bypass of authentication mechanisms. The severity is rated at 7.3 (CVSS v3.1), reflecting a high risk to the confidentiality and integrity of information stored within the system.

## Recommendation

Detection engineering teams should focus on identifying unauthorized SQL injection attempts targeting the affected script. Since no formal patch is currently available, defensive measures should prioritize web application firewall (WAF) rule sets to filter input directed at the patient_info.php endpoint.

- Implement WAF rules to inspect HTTP GET/POST requests for SQL injection patterns (e.g., UNION SELECT, sleep, database-specific metadata queries) targeting the patient_id parameter.
- Monitor web server access logs for anomalous characters or SQL keywords in requests to /patient_info.php.
- Review database audit logs for unauthorized access or execution of administrative commands originating from the web server's service account.
