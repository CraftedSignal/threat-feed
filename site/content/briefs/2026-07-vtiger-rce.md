---
title: 'CVE-2026-23697: Vtiger CRM Authenticated File Upload to RCE'
slug: 2026-07-vtiger-rce
description: An authenticated file upload vulnerability (CVE-2026-23697) in Vtiger CRM before 8.4.0 allows low-privileged users to achieve remote code execution by uploading a `.phar` file containing arbitrary PHP code through the Documents module, which bypasses extension denylists and is directly executable via unauthenticated HTTP requests on Apache 2.4 deployments.
date: "2026-07-07T17:19:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - webserver
  - authenticated-upload
  - apache
  - php
vendors:
  - Vtiger
products:
  - Vtiger CRM < 8.4.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: uploading a .phar file containing arbitrary PHP code
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: allowing unauthenticated HTTP requests to directly execute the uploaded PHP payload
    confidence_band: high
cves:
  - id: CVE-2026-23697
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-23697
rules:
  - title: Detects CVE-2026-23697 Exploitation — Vtiger CRM .phar File Execution
    description: Detects CVE-2026-23697 exploitation — Web requests accessing successfully executed `.phar` files uploaded to Vtiger CRM's web-accessible storage directories, indicative of remote code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.006
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-23697 describes an authenticated file upload vulnerability affecting Vtiger CRM versions prior to 8.4.0. This flaw allows low-privileged users to bypass file extension denylists by uploading `.phar` files containing arbitrary PHP code via the Documents module. The vulnerability stems from the omission of the `.phar` extension in `config.inc.php`'s denylist and the storage of these files in web-accessible directories. When Vtiger CRM is deployed on Apache 2.4, a legacy `.htaccess` configuration designed for Apache 2.2 is silently ignored, enabling unauthenticated attackers to directly execute the uploaded PHP payload. Successful exploitation leads to remote code execution on the underlying server, posing a significant risk for data compromise and system takeover, thus requiring immediate patching for all affected Vtiger CRM instances.

## Attack Chain

1.  A low-privileged user successfully authenticates to a vulnerable Vtiger CRM instance.
2.  The authenticated user navigates to the Vtiger CRM's Documents module.
3.  The user uploads a malicious `.phar` file containing a PHP webshell or other arbitrary PHP code.
4.  Vtiger CRM processes the file upload, inadvertently bypassing the configured extension denylist because the `.phar` extension is not explicitly blocked in `config.inc.php`.
5.  The malicious `.phar` file is stored in a web-accessible directory within the Vtiger CRM deployment on the server.
6.  An unauthenticated attacker sends an HTTP request directly to the path of the uploaded `.phar` file.
7.  If the Vtiger CRM instance is hosted on Apache 2.4, the `.htaccess` file, potentially configured with Apache 2.2 syntax, is ignored by the web server.
8.  The web server executes the PHP code embedded within the `.phar` file, granting the attacker remote code execution capabilities on the server.

## Impact

Successful exploitation of CVE-2026-23697 grants a low-privileged authenticated attacker remote code execution (RCE) on the server hosting Vtiger CRM. This can lead to complete compromise of the Vtiger CRM application, theft or modification of sensitive customer data, deployment of ransomware, or establishment of persistent access for further network penetration. The high CVSS v3.1 score of 8.8 reflects the severity, indicating a critical threat to the confidentiality, integrity, and availability of affected systems. Organizations utilizing Vtiger CRM are at risk of significant operational disruption and data breaches if this vulnerability remains unpatched.

## Recommendation

*   Patch Vtiger CRM to version 8.4.0 or newer immediately to mitigate CVE-2026-23697.
*   Review and ensure web server configurations (e.g., Apache httpd.conf, .htaccess directives) are correctly applied and prevent direct execution of `.phar` files in web-accessible directories, especially for Apache 2.4 deployments.
*   Deploy the provided Sigma rule to your SIEM to detect suspicious access patterns for `.phar` files.
*   Enable comprehensive web server access logging (webserver category) to capture `cs-uri-stem`, `cs-method`, and `sc-status` for all requests, necessary for the rule above.
