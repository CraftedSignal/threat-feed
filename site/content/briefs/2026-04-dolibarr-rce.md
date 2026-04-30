---
title: Dolibarr OS Command Injection via MAIN_ODT_AS_PDF Configuration
slug: 2026-04-dolibarr-rce
description: Dolibarr versions 22.0.4 and earlier are vulnerable to OS Command Injection via the MAIN_ODT_AS_PDF configuration, allowing an authenticated administrator to inject a malicious payload, leading to arbitrary operating system command execution.
date: "2026-04-18T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - dolibarr
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-23500
references:
  - https://github.com/advisories/GHSA-w5j3-8fcr-h87w
rules:
  - title: Dolibarr MAIN_ODT_AS_PDF Command Injection Attempt
    description: Detects attempts to exploit the Dolibarr MAIN_ODT_AS_PDF command injection vulnerability by monitoring process creation with commands containing concatenated commands.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Dolibarr Reverse Shell from ODT Processing
    description: Detects a reverse shell being spawned from a process related to ODT processing in Dolibarr, indicative of command injection.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

Dolibarr, a popular open-source ERP and CRM system, is susceptible to OS Command Injection (RCE) in versions up to 22.0.4. This vulnerability, identified as CVE-2026-23500, stems from insufficient validation of the `MAIN_ODT_AS_PDF` configuration setting. An attacker with administrative privileges can inject malicious commands into this setting, which are then executed by the server during ODT to PDF conversion processes. The vulnerability resides in `htdocs/includes/odtphp/odf.php`, where the application constructs a shell command using the unfiltered `MAIN_ODT_AS_PDF` value. Successful exploitation enables arbitrary command execution on the server, potentially leading to complete system compromise.

## Attack Chain

1. The attacker gains administrative access to the Dolibarr instance, either through credential compromise or social engineering.
2. The attacker navigates to the "Home -> Setup -> Other Setup" section of the Dolibarr administration panel.
3. The attacker modifies the `MAIN_ODT_AS_PDF` configuration constant. The injected payload includes a command separator (`;`) followed by the malicious command. The example uses `jodconverter; echo <base64_encoded_command> | base64 -d | bash`.
4. The attacker navigates to the "Commerce -> New proposal" section.
5. The attacker creates a new proposal in draft status and selects an ODT template.
6. The attacker clicks the "Generate" button, triggering the ODT to PDF conversion process.
7. The application executes the crafted shell command, resulting in command execution.
8. In the proof of concept, the attacker establishes a reverse shell connection to their specified IP address (172.26.0.1) and port (4445), gaining interactive shell access.

## Impact

Successful exploitation allows an attacker with administrator privileges to execute arbitrary commands on the underlying server as the web server user. This can lead to the compromise of sensitive data, modification of application files, and potentially full system compromise. The observed impact includes the establishment of a reverse shell, granting the attacker complete control over the Dolibarr instance. This vulnerability affects Dolibarr installations up to version 22.0.4.

## Recommendation

*   Upgrade Dolibarr to a patched version beyond 22.0.4 to remediate CVE-2026-23500.
*   Monitor process creation events for commands executed with suspicious arguments in `MAIN_ODT_AS_PDF` by deploying the provided Sigma rules.
*   Monitor network connections to unusual external IP addresses originating from the web server, especially following events related to document generation. Block the C2 IP address `172.26.0.1` listed in the IOC table at the network perimeter.
*   Implement strict access controls and regularly audit administrator accounts to prevent unauthorized access to the Dolibarr configuration settings.
