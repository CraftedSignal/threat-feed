---
title: EGroupware Authenticated RCE via Malicious eTemplate Upload (CVE-2026-40187)
slug: 2026-07-egroupware-authenticated-rce
description: An authenticated EGroupware administrator can achieve OS-level Remote Code Execution (RCE) by uploading a malicious eTemplate XML file (`.xet`) containing unescaped backtick characters that lead to shell command execution within a PHP `eval()` call during template processing (CVE-2026-40187), impacting non-Docker or non-hardened EGroupware deployments.
date: "2026-07-07T13:14:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - web-vulnerability
  - php
  - egroupware
  - linux
vendors:
  - EGroupware
products:
  - EGroupware (>= 26.0.20251208, < 26.0.20260113)
  - EGroupware (< 23.1.20260601)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated administrator can achieve OS-level Remote Code Execution (RCE) by uploading a malicious eTemplate XML file (`.xet`)...
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: 'In PHP, backticks inside a double-quoted `eval()` string execute shell commands... `eval(''$name = "$row`id`";'');` // executes shell command: id'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8737-2x9g-xjj7
iocs:
  - type: filepath
    value: /tmp/pwned_egw
  - type: command
    value: touch /tmp/pwned_egw 2>/dev/null
  - type: command
    value: id > /tmp/pwned_egw
ioc_counts:
  command: 2
  filepath: 1
rules:
  - title: Detect CVE-2026-40187 Exploitation - EGroupware RCE via Backtick Shell Commands
    description: Detects CVE-2026-40187 exploitation - Suspicious shell command execution likely originating from an EGroupware web server process, indicative of the authenticated RCE vulnerability.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical vulnerability, CVE-2026-40187, has been identified in EGroupware, allowing an authenticated administrator to achieve OS-level Remote Code Execution (RCE). The flaw resides in the `Widget::expand_name()` method within `api/src/Etemplate/Widget.php`, which passes template widget attribute values into a PHP `eval()` call. Crucially, while double quotes are escaped, backtick characters are not. In PHP, backticks inside a double-quoted `eval()` string trigger shell command execution. This means a malicious eTemplate XML file (`.xet`) uploaded by an administrator can leverage this oversight to execute arbitrary commands on the host server. The vulnerability affects EGroupware versions >= 26.0.20251208 but < 26.0.20260113, and versions < 23.1.20260601. A mitigating factor exists in official Docker deployments, which typically set `disable_functions` in `php.ini` to block `shell_exec()`, but non-Docker or misconfigured installations are fully vulnerable.

## Attack Chain

1.  An attacker gains authenticated administrative access to an EGroupware instance.
2.  The attacker navigates to the Admin -> Filemanager -> VFS Mounts section within EGroupware and clicks "Install custom templates" to mount the `/etemplates` directory with administrative write access.
3.  The attacker crafts a malicious `index.xet` XML file that contains a payload, such as `<textbox id="$row\`touch /tmp/pwned_egw 2>/dev/null\`"/>`, embedding a shell command (`touch /tmp/pwned_egw`) within a widget ID attribute.
4.  The attacker uploads this malicious `index.xet` file to a specific path within the mounted VFS, typically `/etemplates/admin/templates/default/index.xet`, using the EGroupware file manager.
5.  To trigger the vulnerability, the attacker then navigates to an EGroupware admin panel URL, such as `https://<target>/egroupware/index.php?menuaction=admin.admin_ui.index`, which causes the application to load and process the custom template.
6.  During template processing, the `Widget::expand_name()` method is invoked, and the specially crafted widget ID containing the backtick shell command is passed to a PHP `eval()` call.
7.  Due to the unescaped backticks, the PHP interpreter executes the embedded shell command (`touch /tmp/pwned_egw 2>/dev/null`) on the underlying Linux operating system.
8.  The shell command runs with the privileges of the web server user (e.g., `www-data`), creating or modifying files on the server and achieving RCE.

## Impact

Successful exploitation of CVE-2026-40187 allows an attacker with administrative EGroupware credentials to elevate their privileges to arbitrary OS command execution as the web server user. From this position, an attacker can access sensitive system files (e.g., database credentials), establish persistence mechanisms, pivot to other internal systems, or completely compromise the EGroupware server and its data. The vulnerability directly affects any EGroupware installation that is not using the official Docker deployment with its hardened `php.ini` settings or has had `disable_functions` modified. While no specific victim count is provided, all non-hardened EGroupware instances are at risk.

## Recommendation

*   Prioritize patching EGroupware installations to a version that addresses CVE-2026-40187 immediately.
*   Ensure that PHP's `disable_functions` directive in `php.ini` is properly configured to block functions like `exec`, `passthru`, `shell_exec`, `system`, `proc_open`, and `popen` on all EGroupware servers, especially non-Docker deployments.
*   Deploy the provided Sigma rule to detect suspicious process creation activities indicating potential exploitation of CVE-2026-40187.
*   Enable comprehensive `process_creation` logging on all Linux servers hosting EGroupware to capture command line arguments, parent processes, and user information, which is critical for the Sigma rule.
*   Block the execution of the commands identified in the IOCs (e.g., `touch /tmp/pwned_egw`, `id > /tmp/pwned_egw`) at endpoint protection layers where possible.
