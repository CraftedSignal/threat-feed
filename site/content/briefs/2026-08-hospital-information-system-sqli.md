---
title: SQL Injection Vulnerability in Hospital Information System 1.0
slug: 2026-08-hospital-information-system-sqli
description: Hospital Information System 1.0 is vulnerable to unauthenticated remote SQL injection via the 'email' parameter in the User::login function, allowing for unauthorized database access.
date: "2026-08-19T20:43:45Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - code-projects
products:
  - Hospital Information System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
cves:
  - id: CVE-2026-76574
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76574
  - https://vuldb.com/vuln/393038
rules:
  - title: Detects CVE-2026-76574 Exploitation - SQL Injection in User Login Handler
    description: Detects potential SQL injection attempts targeting the email parameter in the Hospital Information System login endpoint.
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch or decommission all internet-facing instances of Hospital Information System 1.0.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-76574 indicates a high-severity RCE/SQLi vulnerability with exploit availability.
  mitigation_plan:
    - priority: immediate
      action: Block or restrict access to login endpoints in web application firewalls for the identified URI.
      owner: IT Operations
      addresses: CVE-2026-76574
      evidence: Source confirms SQL injection vulnerability in specific login function.
---

A critical SQL injection vulnerability, tracked as CVE-2026-76574, has been identified in version 1.0 of the code-projects Hospital Information System. The vulnerability exists within the 'User::login' function located in 'includes/users/UsersController.php'. An unauthenticated, remote attacker can exploit this flaw by supplying malicious SQL payloads through the 'email' argument during the authentication process. Successful exploitation allows an attacker to execute arbitrary SQL commands against the underlying database, potentially resulting in the unauthorized disclosure of sensitive patient information, data modification, or complete compromise of the application's database backend. Publicly available exploit code exists, increasing the risk of active exploitation.

## Impact

The vulnerability affects the Hospital Information System 1.0, a software platform used in clinical or administrative healthcare environments. Successful exploitation may result in a complete breach of confidentiality and integrity of the data stored within the system, potentially exposing patient health information (PHI) and administrative records. Given the sensitivity of the data handled by hospital systems, the impact of unauthorized access is significant.

## Recommendation

Prioritize the immediate decommissioning or patching of all instances of Hospital Information System 1.0. If the product cannot be updated or patched, ensure the application is removed from internet-facing segments immediately. Deploy Web Application Firewall (WAF) rules to inspect incoming HTTP requests for SQL injection signatures specifically targeting the 'email' parameter of login endpoints. Monitor web server access logs for anomalous payloads containing SQL keywords (e.g., SELECT, UNION, SLEEP, WAITFOR) within POST parameters to the identified login URI.
