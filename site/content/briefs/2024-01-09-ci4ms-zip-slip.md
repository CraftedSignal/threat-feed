---
title: CI4MS Backup Restore Zip Slip Vulnerability Leads to RCE
slug: 2024-01-09-ci4ms-zip-slip
description: The CI4MS Backup restore function is vulnerable to Zip Slip, allowing remote code execution by uploading a malicious ZIP archive that writes PHP files to the public web root due to missing validation of entry names during extraction, affecting versions prior to 0.31.5.0.
date: "2026-04-22T17:28:39Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - zip-slip
  - rce
  - code-injection
  - vulnerability
vendors:
  - composer
products:
  - ci4-cms-erp/ci4ms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-xp9f-pvvc-57p4
rules:
  - title: Detect CI4MS Zip Slip via Web Request
    description: Detects potential Zip Slip exploitation attempts in CI4MS by monitoring POST requests to the /backend/backup/restore endpoint with a ZIP archive containing directory traversal sequences.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1068
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Creation via CI4MS Upload
    description: Detects creation of PHP files in web-accessible directories after backup restore, indicating potential RCE exploitation.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - persistence
    techniques:
      - T1068
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A Zip Slip vulnerability exists in the CI4MS backup restore functionality. Authenticated users with backup creation permissions can exploit this by uploading a specially crafted ZIP archive. The vulnerability lies in the `Backup::restore` function (modules/Backup/Controllers/Backup.php), where the application extracts the uploaded ZIP without proper validation of the entry names. This allows an attacker to write files to arbitrary locations, including the public web root, leading to remote code execution (RCE). This vulnerability affects CI4MS versions prior to 0.31.5.0. By crafting a ZIP file with malicious paths, attackers can bypass intended directory restrictions.

## Attack Chain

1. An authenticated user with `create` role accesses the vulnerable `/backend/backup/restore` endpoint.
2. The attacker crafts a malicious ZIP archive containing a PHP file (e.g., `shell.php`) with a path traversing outside the intended extraction directory (e.g., `../../public/shell.php`).
3. The attacker uploads the malicious ZIP archive via the `backup_file` parameter in a POST request.
4. The server moves the uploaded ZIP file to `WRITEPATH . 'uploads/'` without sanitizing or validating the ZIP entry names.
5. The `ZipArchive::extractTo()` function is called on the uploaded ZIP, extracting the malicious file to the specified path `../../public/shell.php`.
6. The PHP file is written to the web root, allowing for remote code execution.
7. The attacker triggers the injected PHP code by sending a request to `/shell.php?c=id`, executing arbitrary commands on the server.
8. The attacker gains complete control over the compromised server, including access to sensitive data and the ability to further compromise the network.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve remote code execution (RCE) on the CI4MS server. This can lead to full compromise of the installation, including the database credentials stored in `.env` and any other sensitive data handled by the site. Because the affected route is in the `csrfExcept` list, this vulnerability can be triggered cross-site against a logged-in administrator, potentially leading to drive-by RCE against site operators. The vulnerability affects versions of `composer/ci4-cms-erp/ci4ms` prior to `0.31.5.0`.

## Recommendation

*   Upgrade `composer/ci4-cms-erp/ci4ms` to version 0.31.5.0 or later to patch the vulnerability as described in GHSA-xp9f-pvvc-57p4.
*   Implement server-side validation of uploaded ZIP archive entry names to prevent path traversal vulnerabilities. Specifically, validate the file paths extracted from the ZIP archive before calling `extractTo()`.
*   Deploy the Sigma rule `Detect CI4MS Zip Slip via Web Request` to identify potential exploitation attempts by monitoring HTTP requests to the vulnerable endpoint.
*   Enable web server logging and monitor for suspicious file creations, especially in web-accessible directories, after ZIP archive uploads, based on the attack chain described above.
