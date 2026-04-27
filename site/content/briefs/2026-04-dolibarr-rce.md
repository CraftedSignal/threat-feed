---
title: Dolibarr OS Command Injection via MAIN_ODT_AS_PDF Configuration
slug: 2026-04-dolibarr-rce
description: Dolibarr versions 22.0.4 and earlier are vulnerable to OS Command Injection via the MAIN_ODT_AS_PDF configuration, allowing an authenticated administrator to inject a malicious payload, leading to arbitrary operating system command execution.
date: "2026-04-18T12:00:00Z"
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

Dolibarr, a popular open-source ERP and CRM system, is susceptible to OS Command Injection (RCE) in versions up to 22.0.4. This vulnerability, identified as CVE-2026-23500, stems from insufficient validation of the `MAIN_ODT_AS_PDF` configuration setting. An attacker with administrative privileges can inject malicious commands into this setting, which are then executed by the server during ODT to PDF conversion processes. The vulnerability resides in `htdocs/includes/odtphp/odf.php`, where the…
