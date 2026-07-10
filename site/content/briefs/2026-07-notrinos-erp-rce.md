---
title: NotrinosERP Authenticated Arbitrary File Upload Leads to Remote Code Execution
slug: 2026-07-notrinos-erp-rce
description: An authenticated user with the 'SA_EMPLOYEE' permission in NotrinosERP can upload arbitrary files, including PHP web shells, through the HRM employee 'Documents' tab, leading to remote code execution due to a lack of extension, MIME, or content validation.
date: "2026-07-10T19:39:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - remote-code-execution
  - file-upload
  - php
  - notrinos
vendors:
  - Notrinos
products:
  - NotrinosERP (<= 1.0.0)
affected_os:
  - Linux
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: The handler writes the raw client-supplied filename — extension intact — into a web served directory with no extension, MIME, or content validation, so a `.php` file is stored under the web root and executes as code, yielding remote code execution on the server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The command in `c` executes on the server.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1189
    technique_name: Drive-by Compromise
    evidence: Remote code execution on the hosting server by any authenticated operator holding the delegable `SA_EMPLOYEE` role (not necessarily an administrator).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qv4m-m73m-8hj7
rules:
  - title: Detect NotrinosERP Web Shell Upload Attempt
    description: Detects attempts to upload malicious PHP files as web shells to NotrinosERP via the HRM employee documents tab due to a lack of file validation.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
      - privilege_escalation
    techniques:
      - T1059
      - T1189
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

An authenticated remote code execution vulnerability exists in NotrinosERP versions up to and including 1.0.0. An attacker with the HR "Manage Employees" permission (`SA_EMPLOYEE`) can exploit this by uploading a file with an arbitrary extension, such as a `.php` web shell, through the employee "Documents" tab. The `tab_documents()` function in `hrm/manage/employees.php` fails to validate file extensions, MIME types, or content, directly storing the client-supplied filename in a web-accessible directory. This allows the attacker to execute arbitrary commands on the server by navigating to the newly uploaded web shell. The vulnerability also includes a stored Cross-Site Scripting (CWE-79) sink due to unescaped file paths, and potential path traversal (CWE-22) on certain PHP builds. This threat enables attackers to gain control over the hosting server, posing a significant risk to data integrity and system availability.

## Attack Chain

1. **Authentication and Initial Access**: An attacker obtains valid credentials for a NotrinosERP user account with the `SA_EMPLOYEE` permission.
2. **CSRF Token Retrieval**: The attacker logs into NotrinosERP and navigates to the HRM employee "Documents" tab (`/hrm/manage/employees.php?_tabs_sel=tab_documents`) to obtain a valid CSRF token (`_token`) from the HTML response.
3. **Malicious File Upload Request**: The attacker crafts a multipart `POST` request to `/hrm/manage/employees.php` including the obtained CSRF token, a valid `doc_type_id`, and a malicious PHP file (e.g., `shell.php`) containing a web shell payload (e.g., `<?php system($_GET['c']); ?>`) in the `doc_file` field.
4. **Arbitrary File Write**: Due to a lack of validation in the `tab_documents()` function, NotrinosERP stores the malicious PHP file with its original `.php` extension verbatim in a web-accessible directory, typically `company/0/documents/employees/`.
5. **Web Shell URL Discovery**: The system echoes the exact path to the uploaded file into a clickable "View" link in the employee "Documents" tab, allowing the attacker to discover the web shell's URL (e.g., `/company/0/documents/employees/1_<unix_ts>_shell.php`).
6. **Remote Code Execution**: The attacker sends a `GET` request to the discovered web shell URL, passing OS commands as a parameter (e.g., `?c=id` or `?c=whoami`), which are then executed by the web server on the underlying operating system.

## Impact

Successful exploitation results in full remote code execution (RCE) on the server hosting NotrinosERP. This allows an authenticated attacker, holding the `SA_EMPLOYEE` role (which may not be an administrator role by default), to compromise the entire system. The impact includes unauthorized access to sensitive data, potential data exfiltration, modification or deletion of critical information, and the ability to establish persistent access. The vulnerability also exposes the system to secondary issues like stored Cross-Site Scripting (XSS), which could impact other users.

## Recommendation

* Deploy the Sigma rule "Detect NotrinosERP Web Shell Upload Attempt" to your SIEM to identify suspicious multipart file uploads.
* Implement robust file upload validation at the web server level, specifically blocking executable extensions like `.php` in the `/company/` directory.
* Ensure web server logs for your NotrinosERP instance include `request_body` content for HTTP POST requests to facilitate detection of malicious payloads.
* Apply available patches for NotrinosERP to address arbitrary file upload vulnerabilities. The suggested fix involves not using client filenames, enforcing extension/MIME allow-lists, and storing uploads outside the web root.
* Restrict `SA_EMPLOYEE` role permissions to only trusted personnel.
