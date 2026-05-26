---
title: Dolibarr ERP CRM 7.0.3 Remote Code Execution via install/step1.php
slug: 2026-05-dolibarr-rce
description: Dolibarr ERP CRM 7.0.3 is vulnerable to remote code evaluation, allowing unauthenticated attackers to execute arbitrary code by injecting PHP code through the db_name parameter, leading to arbitrary command execution.
date: "2026-05-26T13:55:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2018-25357
  - rce
  - code-injection
  - web-application
vendors:
  - Dolibarr
products:
  - Dolibarr ERP CRM 7.0.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2018-25357
    cvss: 9.8
    epss: 0.00156
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25357
  - https://dolibarr.org
  - https://github.com/Dolibarr/dolibarr
  - https://www.exploit-db.com/exploits/44964
  - https://www.vulncheck.com/advisories/dolibarr-erp-crm-remote-code-evaluation-via-install-step1-php
rules:
  - title: Detects CVE-2018-25357 Exploitation — Dolibarr ERP CRM Remote Code Execution via install/step1.php
    description: Detects CVE-2018-25357 exploitation — HTTP POST to /install/step1.php with PHP code injection attempt in the db_name parameter
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2018-25357 Exploitation — Dolibarr ERP CRM Command Execution via check.php
    description: Detects CVE-2018-25357 exploitation — HTTP GET request to /check.php with a cmd parameter indicating command injection attempt after successful RCE via install
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
rules_count: 2
---

Dolibarr ERP CRM 7.0.3 is susceptible to a remote code evaluation vulnerability that permits unauthenticated attackers to execute arbitrary code. The vulnerability is located in the install/step1.php file and can be exploited by injecting PHP code into the db_name parameter via a POST request. This allows attackers to bypass authentication and execute arbitrary PHP code on the server, potentially leading to complete system compromise. This vulnerability was reported in May 2026 but relates to software version 7.0.3. Successful exploitation grants the attacker the ability to execute system commands, read sensitive data, and modify application configurations.

## Attack Chain

1.  The attacker sends a POST request to `/install/step1.php`.
2.  The POST request includes the `db_name` parameter containing malicious PHP code.
3.  The application improperly processes the injected PHP code within the `db_name` parameter.
4.  The injected code is evaluated, allowing the attacker to execute arbitrary commands.
5.  The attacker then accesses the `check.php` endpoint using a GET request.
6.  The GET request includes a `cmd` parameter, specifying the command to be executed.
7.  The server executes the command specified in the `cmd` parameter.
8.  The attacker gains arbitrary code execution on the server.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to execute arbitrary code on the Dolibarr ERP CRM server. This could lead to complete system compromise, including the theft of sensitive data, modification of application configurations, and denial of service. Given the sensitive nature of data typically stored within an ERP CRM system, this vulnerability poses a significant risk to organizations using affected versions of Dolibarr.

## Recommendation

*   Apply available patches or upgrade to a secure version of Dolibarr ERP CRM to remediate CVE-2018-25357.
*   Deploy the provided Sigma rule to detect exploitation attempts against `/install/step1.php`.
*   Monitor web server logs for POST requests to `/install/step1.php` containing suspicious characters in the `db_name` parameter.
