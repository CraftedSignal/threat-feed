---
title: Unauthenticated Remote Code Execution in RSFiles! Joomla Component
slug: 2026-07-rsfiles-rce
description: CVE-2026-57827 allows unauthenticated attackers to achieve remote code execution via an unrestricted file upload vulnerability in the RSFiles! Joomla component.
date: "2026-07-29T21:01:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:rsjoomla:rsfiles\!:*:*:*:*:*:joomla\!:*:*
tags:
  - joomla
  - rce
  - file-upload
  - cve-2026-57827
vendors:
  - RSJoomla
products:
  - RSFiles!
cves:
  - id: CVE-2026-57827
    cvss: 9.8
    epss: 0.00405
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57827
  - https://mysites.guru/blog/rsfiles-unauthenticated-file-upload-rce
rules:
  - title: Detect CVE-2026-57827 Exploitation - Unauthenticated File Upload
    description: Detects exploitation attempts by monitoring HTTP requests to the vulnerable RSFiles! upload task.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-57827 is a critical-severity unauthenticated arbitrary file upload vulnerability affecting the RSFiles! component (com_rsfiles) for Joomla. The vulnerability stems from a design flaw where the component utilizes a split-controller approach, separating the permission-guarded pre-flight check from the actual file-write operation. Because the file-write method in the 'rsfiles.upload' task is unguarded and lacks file-type validation or CSRF protection, an attacker can directly invoke the task to upload arbitrary files, including PHP webshells, to the server. If the component's downloads directory lacks proper .htaccess restrictions - which is the default state for many installations - these files can be executed, leading to full system compromise as the web server user. This flaw affects versions prior to 1.17.12.

## Attack Chain

1. Attacker identifies a target running a vulnerable version of the RSFiles! Joomla component.
2. Attacker crafts a malicious multipart/form-data HTTP POST request containing a PHP webshell.
3. Attacker sends the request to /index.php, targeting the component with the parameters 'option=com_rsfiles' and 'task=rsfiles.upload'.
4. The Joomla frontend controller dispatches the request to the unguarded rsfiles.upload() method, bypassing security checks.
5. The server writes the malicious PHP file to /components/com_rsfiles/downloads/ on the filesystem.
6. Attacker sends an HTTP GET request to the path of the uploaded file to execute arbitrary commands.
7. The server executes the malicious PHP script with the privileges of the web service user (e.g., www-data).

## Impact

Successful exploitation allows for unauthenticated remote code execution, enabling attackers to extract sensitive data such as configuration files, database credentials, and user information. Furthermore, attackers can pivot into internal networks, establish persistent backdoors, or perform full site defacement. The lack of authentication requirements makes this vulnerability highly dangerous, as it allows for automated scanning and mass exploitation of vulnerable Joomla instances.

## Recommendation

- Upgrade the RSFiles! component to version 1.17.12 or higher immediately to enforce permission checks and file-type validation on the upload task.
- Review web server access logs for HTTP POST requests to 'option=com_rsfiles&task=rsfiles.upload' originating from unknown or unauthorized IPs.
- Audit the /components/com_rsfiles/downloads/ directory for suspicious files, particularly those with .php extensions, using the Sigma rules provided below.
- Verify that the downloads folder is configured with appropriate .htaccess or web server configuration to prevent the execution of scripts.
