---
title: CI4MS Theme Upload Zip Slip Vulnerability
slug: 2024-01-02-ci4ms-zip-slip
description: A critical vulnerability exists in ci4ms Theme::upload, where improper validation of ZIP archive entry names allows authenticated users with theme creation permissions to write files to arbitrary locations, leading to remote code execution.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - zip-slip
  - rce
  - codeigniter
  - vulnerability
vendors:
  - composer
products:
  - ci4-cms-erp/ci4ms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/advisories/GHSA-xv3r-vr59-95rg
rules:
  - title: Detect CI4MS Webshell Upload via Theme Exploit
    description: Detects the upload of a ZIP archive containing a PHP webshell with path traversal sequences via the CI4MS theme upload functionality.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Webshell Access After CI4MS Exploit
    description: Detects access to a PHP webshell uploaded via the CI4MS theme upload vulnerability. This rule identifies requests to 'shell.php' with a 'c' parameter for command execution.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The ci4ms application is vulnerable to a Zip Slip attack in its theme upload functionality. This vulnerability, present in versions prior to 0.31.5.0, allows an authenticated backend user with theme creation privileges to upload a specially crafted ZIP archive. Due to the lack of proper validation of entry names during extraction, the attacker can write files to arbitrary locations on the filesystem. This is achieved by including malicious path traversal sequences (e.g., `../../`) in the ZIP archive's entry names. The vulnerability allows an attacker to place a PHP webshell in the public web root, enabling remote code execution on the server. This issue poses a significant risk to organizations using ci4ms, as it allows attackers to fully compromise the installation and access sensitive data.

## Attack Chain

1. An attacker authenticates to the ci4ms backend with an account possessing the theme `create` role.
2. The attacker crafts a malicious ZIP archive containing a PHP webshell (e.g., `shell.php`) and an `info.xml` file for theme validation. The webshell is placed with a path traversal sequence, such as `../../public/shell.php`.
3. The attacker navigates to the theme upload functionality within the ci4ms backend, accessible via the `backend/themes/themesUpload` route.
4. The attacker uploads the malicious ZIP archive through the web interface, triggering the `Theme::upload` function.
5. The `ZipArchive::extractTo()` function extracts the contents of the ZIP archive to a temporary directory (`WRITEPATH . 'tmp/' . str_replace('_theme.zip', '', $file->getName()) . '/'`) without validating entry names.
6. Due to the path traversal sequences in the ZIP archive, the PHP webshell is written to the web server's document root (e.g., `/var/www/html/public/shell.php`).
7. The attacker accesses the PHP webshell via a web browser or command-line tool like `curl`, passing commands to be executed on the server (e.g., `https://target.example.com/shell.php?c=id`).
8. The webserver executes the attacker-supplied command, granting the attacker remote code execution on the compromised system.

## Impact

Successful exploitation of this Zip Slip vulnerability allows an attacker to gain remote code execution on the ci4ms server. This grants the attacker full control over the server, potentially leading to the exfiltration of sensitive data, including database credentials stored in the `.env` file. The attacker can also modify or delete website content, install malware, or use the compromised server as a launching point for further attacks. This vulnerability affects versions of ci4ms prior to 0.31.5.0, and impacts any installation where an attacker can obtain theme creation privileges.

## Recommendation

*   Upgrade ci4ms to version 0.31.5.0 or later to patch CVE-2026-41203.
*   Deploy the Sigma rule `Detect CI4MS Webshell Upload via Theme Exploit` to detect attempts to upload malicious themes containing webshells.
*   Implement input validation and sanitization measures to prevent path traversal attacks in file upload functionalities.
*   Restrict theme creation privileges to only trusted administrators and monitor theme creation activity for suspicious behavior.
