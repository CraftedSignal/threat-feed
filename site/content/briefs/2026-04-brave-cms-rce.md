---
title: Brave CMS Unrestricted File Upload Leads to Remote Code Execution
slug: 2026-04-brave-cms-rce
description: Brave CMS versions prior to 2.0.6 contain an unrestricted file upload vulnerability within the CKEditor upload functionality in the ckupload method, allowing authenticated users to upload executable PHP scripts and achieve Remote Code Execution.
date: "2026-04-06T18:16:42Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-35164
  - rce
  - file-upload
  - brave-cms
  - ckeditor
  - php
  - webserver
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35164
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35164
  - https://github.com/Ajax30/BraveCMS-2.0/security/advisories/GHSA-2j4q-6p52-4rhw
rules:
  - title: Detect Access to Suspicious PHP Files
    description: Detects attempts to access PHP files in common upload directories, which may indicate exploitation of file upload vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHP File Uploads via CKEditor
    description: Detects potential PHP file uploads via the CKEditor upload functionality.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Brave CMS, an open-source content management system, is vulnerable to an unrestricted file upload vulnerability (CVE-2026-35164) in versions prior to 2.0.6. The vulnerability resides within the CKEditor upload functionality, specifically in the `ckupload` method located in `app/Http/Controllers/Dashboard/CkEditorController.php`. The application fails to properly validate the types of uploaded files, relying solely on user-provided input. This lack of validation enables an authenticated user to upload malicious PHP scripts, leading to arbitrary code execution on the server. The vulnerability was reported on April 6, 2026, and is fixed in Brave CMS version 2.0.6. Organizations using affected versions of Brave CMS are at risk of complete system compromise.

## Attack Chain

1.  Attacker authenticates to the Brave CMS application as a user with upload privileges.
2.  The attacker navigates to a page or functionality within the CMS that utilizes the CKEditor for content creation or editing.
3.  The attacker uses the CKEditor's upload functionality to upload a malicious PHP script disguised as a legitimate file type (e.g., image).
4.  The `ckupload` method in `app/Http/Controllers/Dashboard/CkEditorController.php` processes the uploaded file without proper validation of the file type or content.
5.  The malicious PHP script is stored on the server in a publicly accessible directory.
6.  The attacker crafts a request to directly access the uploaded PHP script via its URL.
7.  The web server executes the PHP script, granting the attacker the ability to run arbitrary commands on the server.
8.  The attacker establishes persistence, installs a web shell, and performs lateral movement within the network, escalating privileges as needed to achieve their objectives.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary PHP code on the affected Brave CMS server. This can lead to complete compromise of the CMS instance, including unauthorized access to sensitive data, modification of website content, and potential lateral movement to other systems on the network. The CVSS v3.1 base score for this vulnerability is 8.8, indicating a high severity level. Organizations running vulnerable versions of Brave CMS are at risk of data breaches, website defacement, and further exploitation of their infrastructure.

## Recommendation

*   Upgrade Brave CMS to version 2.0.6 or later to remediate the unrestricted file upload vulnerability (CVE-2026-35164).
*   Implement server-side file validation to prevent the upload of malicious files, regardless of file extension.
*   Monitor web server logs for suspicious activity related to file uploads and execution of PHP scripts.
*   Deploy the following Sigma rule to detect attempts to access potentially malicious PHP files in the web server's upload directories.
