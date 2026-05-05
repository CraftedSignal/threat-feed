---
title: Grav CMS Multiple RCE Vulnerabilities
slug: 2024-01-grav-rce
description: Multiple critical and high severity remote code execution vulnerabilities exist in Grav CMS due to unsafe unserialize functions, command injection in git clone, and an SSTI blocklist bypass, impacting versions prior to 2.0.0-beta.2.
date: "2024-01-09T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - rce
  - unserialize
  - command-injection
  - ssti
vendors:
  - Grav
products:
  - Grav CMS
  - composer/getgrav/grav (< 2.0.0-beta.2)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
references:
  - https://github.com/advisories/GHSA-vj3m-2g9h-vm4p
rules:
  - title: Detect Unsafe PHP Unserialize
    description: Detects potential exploitation attempts of PHP unserialize vulnerabilities in web server logs.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect Git Clone Command Injection
    description: Detects potential command injection attempts via git clone commands executed by the web server.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Twig SSTI attempts via Array Reduce
    description: Detects usage of twig_array_reduce function to bypass SSTI blocklists
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Multiple remote code execution (RCE) vulnerabilities have been identified in Grav CMS, a flat-file content management system. These vulnerabilities, including unsafe unserialize functions in JobQueue, FileCache, and Session, a command injection in git clone, and a server-side template injection (SSTI) blocklist bypass, allow attackers to execute arbitrary code on affected systems. The vulnerabilities are present in Grav CMS versions prior to 2.0.0-beta.2 and were patched in commit c66dfeb5f and 38685ac25. Successful exploitation of these vulnerabilities could lead to complete system compromise, data theft, and disruption of service. The most concerning are the unserialize issues, as they do not require admin access and can be triggered by any file write primitive.

## Attack Chain

1. An attacker gains the ability to write files to the Grav CMS server, either through an existing vulnerability (e.g., file upload) or misconfiguration.
2. The attacker crafts a serialized PHP object containing malicious code.
3. For JobQueue or FileCache exploitation, the attacker writes this serialized object to the appropriate cache file location. For Session exploitation, the attacker sets a crafted serialized object within a session variable.
4. The Grav CMS application deserializes the crafted object using `unserialize()`, without proper input validation.
5. The deserialization process instantiates the malicious object, triggering the execution of arbitrary code. Specifically, the JobQueue vulnerability allows direct RCE via `Job::exec → call_user_func_array`.
6. For the git clone command injection, an administrator attempts to install a malicious plugin or theme. The attacker injects commands into the `branch`, `url`, or `path` parameters within the plugin's or theme's configuration.
7. The `InstallCommand.php` script executes a `git clone` command, incorporating the attacker-controlled parameters without proper sanitization.
8. The injected commands are executed on the server, granting the attacker arbitrary code execution.

## Impact

Successful exploitation of these vulnerabilities can lead to complete system compromise. An attacker could gain unauthorized access to sensitive data, modify website content, install backdoors, or use the compromised server as a launchpad for further attacks. The unserialize vulnerabilities are especially critical as they do not require administrative privileges if an attacker can write to the cache directory. The impact includes potential data theft, service disruption, and reputational damage.

## Recommendation

*   Upgrade Grav CMS to version 2.0.0-beta.2 or later to patch the vulnerabilities described in this brief.
*   Implement the Sigma rule `Detect Unsafe PHP Unserialize` to identify attempts to exploit the unserialize vulnerabilities in web server logs.
*   Review and harden file upload and file management functionalities to prevent unauthorized file writes to the Grav CMS server.
*   Monitor process creation events for git commands executed by the web server user, using the Sigma rule `Detect Git Clone Command Injection`.
