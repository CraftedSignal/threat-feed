---
title: FacturaScripts Path Traversal to Remote Code Execution Vulnerability
slug: 2026-07-facturascripts-path-traversal-rce
description: An authenticated attacker can exploit a path traversal vulnerability (GHSA-hgjx-r89m-m7v4) in FacturaScripts versions 2025 through 2026.2's file upload functionality to write arbitrary files outside intended directories, leading to remote code execution as the web-server user.
date: "2026-07-14T20:54:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-application
  - path-traversal
  - remote-code-execution
  - php
vendors:
  - FacturaScripts
products:
  - FacturaScripts (>= 2025, <= 2026.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated user submitting a filename containing `../` segments can write the uploaded content to any directory writable by the web-server user, escaping the intended `MyFiles/` location.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: 'The same primitive can write an Apache override into `Dinamic/Assets/`: 1. Upload with filename `../Dinamic/Assets/.htaccess` and body `AddType application/x-httpd-php .png`'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'The same primitive can write an Apache override into `Dinamic/Assets/`: ... 2. Upload with filename `../Dinamic/Assets/x.png` containing a PHP payload ... 3. Request `https://target/Dinamic/Assets/x.png` — Apache hands it to the PHP handler per the uploaded `.htaccess`'
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: full remote code execution as the web-server user.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Combined with `.htaccess` not being in `BLOCKED_EXTENSIONS`, the primitive escalates from arbitrary file write to remote code execution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-hgjx-r89m-m7v4
rules:
  - title: Detects GHSA-hgjx-r89m-m7v4 Exploitation - FacturaScripts .htaccess Upload via Path Traversal
    description: Detects attempts to upload a `.htaccess` file using path traversal in FacturaScripts' upload endpoints, which is a step towards RCE via GHSA-hgjx-r89m-m7v4.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1546.006
    data_sources:
      - webserver
  - title: Detects GHSA-hgjx-r89m-m7v4 Exploitation - FacturaScripts PHP Payload Upload via Path Traversal
    description: Detects attempts to upload a PHP payload (disguised as .png) using path traversal in FacturaScripts' upload endpoints, as part of the RCE chain for GHSA-hgjx-r89m-m7v4.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A critical path traversal vulnerability, tracked as GHSA-hgjx-r89m-m7v4, exists in FacturaScripts versions 2025 up to and including 2026.2. The flaw resides in the `UploadedFile::move()` method, which incorrectly concatenates the destination path with the unsanitized `getClientOriginalName()` from user-supplied filenames. This allows an authenticated attacker to inject `../` segments into filenames during file uploads, bypassing the intended `MyFiles/` directory and writing arbitrary files to any location writable by the web server user. This primitive can be leveraged to achieve remote code execution (RCE) by uploading a specially crafted Apache `.htaccess` file into directories directly served by Apache (such as `Dinamic/Assets/`), followed by a PHP payload disguised with a benign extension like `.png`. The vulnerability affects any user with upload privileges, including non-administrative roles.

## Attack Chain

1. An authenticated attacker obtains valid credentials or an API token with file upload permissions (e.g., to `/api/3/uploadfiles` or `/api/3/attachedfiles`).
2. The attacker crafts an HTTP POST request to a vulnerable upload endpoint (e.g., `/api/3/uploadfiles`), submitting a file with a malicious filename containing path traversal sequences, such as `../Dinamic/Assets/.htaccess`.
3. The `UploadedFile::move()` method in FacturaScripts processes this filename without proper sanitization, concatenating it with the base directory, causing the `.htaccess` file to be written into the `Dinamic/Assets/` directory.
4. The uploaded `.htaccess` file contains a directive like `AddType application/x-httpd-php .png`, instructing Apache to parse `.png` files as PHP scripts within that directory.
5. The attacker then initiates a second file upload using the same path traversal technique, delivering a file named `../Dinamic/Assets/x.png` containing arbitrary PHP code (e.g., `<?php phpinfo(); ?>`).
6. The PHP payload is written to `Dinamic/Assets/x.png` due to the path traversal vulnerability.
7. The default Apache configuration for FacturaScripts (from `htaccess-sample`) excludes `Dinamic/Assets/` from `index.php` rewrite rules, meaning files in this directory are served directly by Apache.
8. The attacker accesses `https://target/Dinamic/Assets/x.png` via a web browser or HTTP request, causing the Apache web server to execute the uploaded PHP code as the web-server user, resulting in remote code execution.

## Impact

Successful exploitation of GHSA-hgjx-r89m-m7v4 allows an authenticated attacker to achieve full remote code execution (RCE) as the web-server user. This includes the ability to execute arbitrary commands, steal data, deface the website, or compromise the server hosting FacturaScripts. The attacker can also inject client-side script by overwriting legitimate JavaScript or CSS files within the `Dinamic/Assets/` directory, leading to session takeover for administrators or other users on subsequent page loads. The vulnerability affects a wide range of users, as even non-administrative roles often possess the necessary upload permissions.

## Recommendation

* Deploy the provided Sigma rules to your SIEM solution to detect attempts to upload malicious `.htaccess` or PHP files using path traversal.
* Monitor `webserver` logs for HTTP POST requests to `/api/3/uploadfiles`, `/api/3/attachedfiles`, or other file upload endpoints that include `../` sequences in the filename or `cs-uri-query`.
* Patch FacturaScripts to a version greater than 2026.2 immediately upon availability of a fix, as specified in the GitHub Security Advisory GHSA-hgjx-r89m-m7v4.
* Implement strong logging for `webserver` activity, particularly for POST requests and file uploads, to enable detection of the described attack chain.
* Ensure server configurations enforce least privilege for the web-server user to minimize potential damage from RCE.
