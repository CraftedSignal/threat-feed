---
title: 'CVE-2026-60102: Horde VFS OS Command Injection Vulnerability'
slug: 2026-07-horde-vfs-os-command-injection
description: CVE-2026-60102 describes an OS command injection vulnerability in the Horde Virtual File System (VFS) API before version 3.0.1, specifically within the Horde_Vfs_Smb driver, which allows authenticated attackers to inject arbitrary shell commands via user-controlled filenames during file operations, leading to arbitrary command execution on the underlying system.
date: "2026-07-08T17:20:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - os-command-injection
  - rce
  - webserver
  - horde
  - cve
vendors:
  - Horde
products:
  - Horde Virtual File System (VFS) API < 3.0.1
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated attackers can inject arbitrary shell commands through user-controlled filenames... interpolated into a double-quoted shell context and executed via proc_open() through /bin/sh -c before smbclient runs, resulting in arbitrary command execution on the underlying system.
    confidence_band: high
cves:
  - id: CVE-2026-60102
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-60102
rules:
  - title: Detects CVE-2026-60102 Exploitation - Horde VFS OS Command Injection
    description: Detects CVE-2026-60102 exploitation attempts via HTTP requests targeting Horde VFS API with command substitution sequences in filenames. This indicates an OS command injection attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
---

A critical OS command injection vulnerability, tracked as CVE-2026-60102, has been identified in the Horde Virtual File System (VFS) API, affecting versions prior to 3.0.1. This flaw resides within the Horde_Vfs_Smb driver's `_escapeShellCommand()` method, which fails to properly sanitize command substitution sequences. Authenticated attackers can exploit this by crafting malicious filenames containing unescaped shell commands and performing standard file operations such as upload, folder creation, rename, or deletion. These malicious filenames are then interpolated into a double-quoted shell context and executed via `proc_open()` through `/bin/sh -c` before the `smbclient` utility runs. Successful exploitation results in arbitrary command execution on the server hosting the Horde VFS, granting attackers significant control over the compromised system. This vulnerability poses a severe risk to organizations using affected Horde VFS installations, as it allows for unauthorized code execution and potential data compromise.

## Attack Chain

1. **Initial Access**: An attacker gains authenticated access to a vulnerable Horde Virtual File System (VFS) API instance using legitimate or compromised credentials.
2. **Craft Malicious Input**: The attacker prepares a filename that includes OS command substitution sequences (e.g., `$(id)`, `| ls -la`, `file.php;rm -rf /`).
3. **Trigger File Operation**: The attacker initiates a file operation, such as uploading a file, creating a folder, renaming a file/folder, or deleting a file/folder, providing the malicious filename.
4. **Vulnerable Code Execution**: The Horde_Vfs_Smb driver processes the request, and the `_escapeShellCommand()` method is called to sanitize the filename before passing it to an underlying system command.
5. **Failed Sanitization**: Due to the vulnerability, `_escapeShellCommand()` fails to properly sanitize the command substitution sequences within the attacker-controlled filename.
6. **Command Injection**: The unsanitized malicious filename is interpolated into a double-quoted shell context that is passed to `proc_open()`.
7. **Arbitrary Command Execution**: The `/bin/sh -c` command interpreter executes the injected arbitrary shell commands on the underlying system, leading to full compromise.

## Impact

Successful exploitation of CVE-2026-60102 allows authenticated attackers to achieve arbitrary command execution on the server hosting the Horde VFS API. This means attackers can execute any command with the privileges of the web server process, potentially leading to full system compromise, data exfiltration, installation of backdoors, defacement of web content, or further network lateral movement. For organizations relying on Horde VFS for document management or collaboration, this vulnerability can result in significant operational disruption, data breaches, and reputational damage. The NVD rates this with a CVSS v3.1 Base Score of 8.8, indicating high severity.

## Recommendation

* Immediately patch CVE-2026-60102 by upgrading Horde Virtual File System (VFS) API to version 3.0.1 or later on all affected systems.
* Deploy the Sigma rule below to detect attempts to exploit CVE-2026-60102.
* Enable comprehensive web server access logging (e.g., Apache, Nginx) to capture `cs-uri-query` and `cs-uri-stem` details for all requests, which can be used by the detection rule.
* Monitor `proc_open()` calls for unusual shell command execution patterns if your endpoint detection and response (EDR) or system logging provides this visibility.
