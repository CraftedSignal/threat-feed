---
title: Blind SQL Injection in EasyAppointments
slug: 2026-09-easyappointments-sqli
description: EasyAppointments versions 1.5.1 and earlier contain a blind SQL injection vulnerability in search endpoints that allows authenticated attackers to extract sensitive database content via malicious 'order_by' parameters.
date: "2026-09-01T14:31:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:easyappointments:easyappointments:*:*:*:*:*:*:*:*
tags:
  - webapps
  - sqli
  - cve-2025-50455
vendors:
  - EasyAppointments
products:
  - EasyAppointments (<= 1.5.1)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A blind SQL injection vulnerability exists in the order_by parameter of the /index.php/customers/search endpoint.
    confidence_band: high
cves:
  - id: CVE-2025-50455
    cvss: 9.1
    epss: 0.00552
references:
  - https://www.exploit-db.com/exploits/52667
  - https://github.com/alextselegidis/easyappointments/security/advisories/GHSA-w45h-26pc-4gr9
  - https://github.com/alextselegidis/easyappointments/commit/0f0d71cfe0692daed9aee59bc424ce2a084fd59e
rules:
  - title: Detects CVE-2025-50455 Exploitation - Blind SQL Injection via order_by
    description: Detects exploitation attempts against EasyAppointments by identifying suspicious SQL keywords within the order_by parameter in POST requests to search endpoints.
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
    - action: Patch EasyAppointments to a non-vulnerable version.
      owner: IT Operations
      due: 24h
      evidence: CVE-2025-50455 indicates vulnerability in <= 1.5.1.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to block identified SQLi payloads.
      owner: SOC
      addresses: CVE-2025-50455
      evidence: Source provides specific SQLi techniques.
---

EasyAppointments versions 1.5.1 and earlier are affected by a blind SQL injection vulnerability (CVE-2025-50455) within the 'order_by' parameter processed by the application's search endpoints, including '/index.php/customers/search', '/index.php/admins/search', and others. The vulnerability exists because the CodeIgniter 3 framework's Query Builder 'order_by' function fails to adequately sanitize input, specifically allowing parenthesized subqueries to bypass identifier protection mechanisms. An authenticated attacker can leverage this flaw to perform both boolean-based and time-based data exfiltration. Successful exploitation allows an attacker to enumerate database tables, columns, user email addresses, and account password hashes. The vulnerability was disclosed alongside a functional Proof of Concept (PoC) script, significantly increasing the risk of exploitation for unpatched instances.

## Attack Chain

1. Attacker navigates to the application login page at /index.php/login to obtain a CSRF token.
2. Attacker authenticates as a user by sending a POST request to /index.php/login/validate with valid credentials and a valid CSRF token.
3. Attacker identifies a vulnerable search endpoint, such as /index.php/customers/search, which accepts the 'order_by' parameter.
4. Attacker crafts a malicious 'order_by' parameter containing a SQL subquery (e.g., using 'SLEEP()' for time-based or 'IF' for boolean-based inference).
5. The application backend processes the unsanitized 'order_by' parameter through the CodeIgniter 3 Query Builder.
6. The database executes the injected SQL, causing the application to return different responses or introduce time delays based on the boolean result of the subquery.
7. Attacker systematically iterates through bits or characters of target database fields to exfiltrate sensitive data.

## Impact

Successful exploitation allows for the full extraction of database contents. Targeted data includes administrator credentials, system configuration details, and user personally identifiable information (PII). In environments with misconfigured 'secure_file_priv' settings, the vulnerability could potentially be escalated to local file read or arbitrary file write, posing a severe risk of unauthorized access to the underlying Linux host.

## Recommendation

1. Upgrade to a version of EasyAppointments where CVE-2025-50455 is addressed.
2. Implement strict input validation on all application parameters that influence SQL query construction.
3. Deploy web application firewall (WAF) rules to detect and block HTTP POST requests containing SQL syntax keywords (e.g., SELECT, SLEEP, IF, ORDER BY) in the 'order_by' parameter.
4. Monitor web server access logs for anomalous time-delayed responses (e.g., latency exceeding 5 seconds) to requests directed at the identified search endpoints.
5. Audit database user permissions to ensure the application user follows the principle of least privilege, specifically restricting access to 'information_schema' and file system operations.
