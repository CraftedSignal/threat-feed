---
title: Grav CMS Remote Code Execution via Malicious Plugin Upload
slug: 2024-01-grav-rce
description: A remote code execution vulnerability exists in Grav CMS versions prior to 2.0.0-beta.2, allowing an authenticated administrator to upload a malicious plugin via a ZIP file, leading to arbitrary PHP code execution and web shell deployment.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - gravcms
  - plugin upload
vendors:
  - getgrav
products:
  - grav (< 2.0.0-beta.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
references:
  - https://github.com/advisories/GHSA-w48r-jppp-rcfw
iocs:
  - type: url
    value: http://127.0.0.1/shell.php?cmd=id
  - type: url
    value: http://127.0.0.1/shell.php?cmd=whoami
ioc_counts:
  url: 2
rules:
  - title: Detect Grav CMS Malicious Plugin Installation via Direct Install
    description: Detects the upload of ZIP files containing PHP files to the /user/plugins/ directory via the direct install endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Web Shell Creation via Malicious Plugin
    description: Detects the creation of a shell.php file in the web root directory, indicative of web shell deployment via malicious plugin.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The vulnerability, CVE-2026-42607, resides in Grav CMS, a flat-file content management system. An authenticated user with administrative privileges can exploit a flaw in the "Direct Install" feature of the Admin plugin to achieve Remote Code Execution (RCE). This is accomplished by uploading a specially crafted ZIP file containing a malicious plugin. While the system attempts to block direct .php file uploads, it does not properly inspect the contents of uploaded ZIP archives. This allows an attacker to bypass security measures and inject arbitrary PHP code, potentially leading to complete server compromise. The vulnerability affects Grav versions prior to 2.0.0-beta.2, with a partial fix addressing path traversal issues but not the core issue of malicious plugin code execution.

## Attack Chain

1.  Attacker authenticates to the Grav admin panel with valid administrative credentials, or exploits a separate vulnerability (CSRF/Session Hijacking) to act as an admin.
2.  Attacker navigates to the "Direct Install" tool within the Admin plugin, typically found under the tools section of the admin panel (/admin/tools/direct-install).
3.  Attacker prepares a malicious plugin, including a shellplugin.php file designed to create a web shell (shell.php) with system command execution capabilities.
4.  The malicious plugin and associated files (blueprints.yaml, shellplugin.yaml) are compressed into a ZIP archive (shellplugin.zip).
5.  Attacker uploads the malicious ZIP archive (shellplugin.zip) through the direct install form, bypassing client-side and initial server-side checks.
6.  The server extracts the contents of the ZIP archive directly into the `/user/plugins/` directory without proper validation of the PHP files within the archive.
7.  The attacker triggers the execution of the malicious plugin by accessing the base URL. The plugin creates a web shell named `shell.php` in the GRAV_ROOT directory.
8.  The attacker leverages the dropped web shell (shell.php) to execute arbitrary system commands on the server, achieving Remote Code Execution (RCE).

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary PHP code on the target server. This can lead to a full system compromise, including the ability to read sensitive data, modify files, install malware, and pivot to other systems on the network. The vulnerability impacts any Grav installation with the Admin plugin enabled where an attacker has gained administrative access. The impact is critical, potentially leading to complete server control and significant data loss or service disruption. While a partial fix addresses path traversal, the ability to upload and execute malicious PHP code remains a significant risk.

## Recommendation

*   Upgrade Grav CMS to version 2.0.0-beta.2 or later to incorporate the partial fix that addresses path traversal vulnerabilities described in the overview.
*   Implement the Sigma rule "Detect Grav CMS Malicious Plugin Installation via Direct Install" to identify attempts to upload ZIP files containing suspicious PHP code to `/user/plugins/` directory.
*   Monitor web server logs for access to `/shell.php` with `cmd` parameters, as this indicates potential exploitation, as seen in the IOCs.
*   Restrict administrative access to trusted users and implement multi-factor authentication to prevent unauthorized access to the Grav admin panel.
