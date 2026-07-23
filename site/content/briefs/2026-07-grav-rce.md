---
title: Grav CMS Remote Code Execution Vulnerability (CVE-2026-65608)
slug: 2026-07-grav-rce
description: An authenticated remote code execution vulnerability (CVE-2026-65608) in Grav CMS versions 1.7.0 through 2.0.8 allows attackers with Flex directory create/update permissions to execute arbitrary shell commands due to improper input validation in `FlexDirectory::dynamicDataField()`.
date: "2026-07-23T12:21:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - RCE
  - CMS
  - PHP
  - Grav
  - web-exploitation
vendors:
  - Grav
products:
  - Grav (>= 1.7.0, < 2.0.9)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Any authenticated user with create or update permission on any Flex-based directory... can execute arbitrary shell commands on the server.
    confidence_band: high
cves:
  - id: CVE-2026-65608
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65608
rules:
  - title: Detect Grav CVE-2026-65608 Exploitation - Linux Web Server Spawning Shell
    description: Detects CVE-2026-65608 exploitation where a Grav PHP web server process (e.g., Apache, Nginx, PHP-FPM) spawns a shell interpreter process on a Linux system. This indicates successful remote code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1059.006
    data_sources:
      - process_creation
      - linux
  - title: Detect Grav CVE-2026-65608 Exploitation - Windows Web Server Spawning Shell
    description: Detects CVE-2026-65608 exploitation where a Grav PHP web server process (e.g., IIS w3wp.exe, Apache HTTPD) spawns a command interpreter process on a Windows system. This indicates successful remote code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.003
      - T1059.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Grav CMS versions 1.7.0 and later, up to but not including 2.0.9, are affected by a remote code execution (RCE) vulnerability identified as CVE-2026-65608. The flaw resides within the `FlexDirectory::dynamicDataField()` function, which is responsible for resolving `blueprint data-*@:` directives. This function improperly validates attacker-influenced input by using `call_user_func_array()` without restricting dangerous PHP functions such as `exec`, `system`, `passthru`, or `shell_exec`. This oversight bypasses existing validation mechanisms introduced in `Blueprint::dynamicData()` (CVE-2024-XXXX, GHSA-fj2p-qj2f-74v5). Any authenticated user possessing create or update permissions on a Flex-based directory, such as Flex Users, Flex Pages, Flex Objects, or custom Flex types, can exploit this vulnerability to execute arbitrary shell commands on the server, posing a critical risk to the integrity and availability of the Grav instance.

## Attack Chain

1. **Initial Access**: An attacker obtains valid credentials for a Grav CMS user account that has "create or update permission on any Flex-based directory (Flex Users, Flex Pages, Flex Objects, or custom Flex types)."
2. **Exploitation Request**: The authenticated attacker crafts and sends an HTTP request to the Grav instance designed to create or update an entry within one of the vulnerable Flex-based directories.
3. **Payload Injection**: Within the malicious HTTP request, the attacker embeds a payload disguised as a `blueprint data-*@:` directive, specifically crafted to call dangerous PHP functions like `exec`, `system`, `passthru`, or `shell_exec` with arbitrary shell commands as arguments.
4. **Vulnerable Function Call**: The Grav application processes the request. The `FlexDirectory::dynamicDataField()` function is invoked to resolve the attacker-controlled `blueprint data-*@:` directive.
5. **Validation Bypass**: `FlexDirectory::dynamicDataField()` performs a basic `is_callable()` check on the attacker-supplied function name but fails to prevent the invocation of dangerous functions, effectively bypassing the intended security validation.
6. **Command Execution**: The `call_user_func_array()` PHP function is executed with the attacker-controlled dangerous function and arbitrary shell commands, leading to their execution on the server.
7. **Impact**: The arbitrary shell commands are executed on the underlying server with the privileges of the web server process, granting the attacker remote code execution capabilities.

## Impact

Successful exploitation of CVE-2026-65608 leads to authenticated remote code execution on the server hosting the Grav CMS instance. Attackers can execute arbitrary shell commands, potentially leading to full system compromise, data exfiltration, defacement, or the installation of further malware (e.g., web shells, backdoors). While no specific victim counts or targeted sectors are available, any organization utilizing affected Grav CMS versions with authenticated users could be at risk.

## Recommendation

* **Patch**: Immediately upgrade Grav CMS to version 2.0.9 or higher to remediate CVE-2026-65608.
* **Monitor Process Creation**: Deploy the Sigma rules "Detect Grav CVE-2026-65608 Exploitation - Linux Web Server Spawning Shell" and "Detect Grav CVE-2026-65608 Exploitation - Windows Web Server Spawning Shell" to your SIEM to detect suspicious process creations originating from web server processes, which could indicate successful exploitation.
* **Review Permissions**: Audit Grav CMS user permissions, especially those related to creating or updating Flex-based directories, ensuring the principle of least privilege is applied.
* **Web Application Firewall**: Implement or update WAF rules to detect and block suspicious requests targeting Grav CMS endpoints that modify Flex directory entries, looking for shell command metacharacters or dangerous function calls in request bodies.
