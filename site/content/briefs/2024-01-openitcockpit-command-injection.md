---
title: openITCOCKPIT Command Injection Vulnerability (CVE-2026-24893)
slug: 2024-01-openitcockpit-command-injection
description: openITCOCKPIT Community Edition before 5.5.2 is vulnerable to command injection, allowing authenticated users with host modification privileges to execute arbitrary OS commands on the monitoring backend via crafted host attributes in monitoring command templates.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - command-injection
  - rce
  - openitcockpit
vendors:
  - openITCOCKPIT
products:
  - openITCOCKPIT Community Edition
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-24893
    cvss: 8.8
    epss: 0.01398
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24893
rules:
  - title: openITCOCKPIT Command Injection - Process Creation
    description: Detects command injection attempts in openITCOCKPIT by monitoring for suspicious process creation events related to injected commands.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: openITCOCKPIT Command Injection - Web Logs
    description: Detects potential command injection attempts in openITCOCKPIT via web server logs by looking for suspicious patterns in URI queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: openITCOCKPIT Suspicious File Creation
    description: Detects potential exploitation of openITCOCKPIT by monitoring for files created in /tmp by the Icinga process.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - file_event
      - linux
rules_count: 3
---

openITCOCKPIT is an open-source monitoring tool used for various monitoring engines. A critical command injection vulnerability, identified as CVE-2026-24893, affects openITCOCKPIT Community Edition versions prior to 5.5.2. This vulnerability allows an authenticated user with the permission to add or modify hosts to execute arbitrary operating system commands on the monitoring backend. The root cause lies in the insecure handling of user-controlled host attributes, specifically the host address. These attributes are expanded into monitoring command templates without proper validation, escaping, or quoting. This lack of input sanitization allows attackers to inject malicious commands. Successful exploitation results in remote code execution on the openITCOCKPIT server. Organizations using vulnerable versions of openITCOCKPIT are at high risk.

## Attack Chain

1. An authenticated user logs into the openITCOCKPIT web interface with privileges to modify host configurations.
2. The attacker navigates to the host configuration panel and selects to add or modify a host.
3. The attacker enters a malicious payload within the host address field, injecting OS commands (e.g., `127.0.0.1; whoami > /tmp/poc.txt`).
4. openITCOCKPIT stores the crafted host address without proper sanitization.
5. The monitoring engine (Nagios/Icinga) processes the host configuration, expanding the host address into a monitoring command template.
6. The monitoring engine executes the template via a shell. The injected OS command within the host address is executed due to the lack of escaping or quoting.
7. The injected command executes on the openITCOCKPIT server with the privileges of the monitoring engine.
8. The attacker gains remote code execution, potentially leading to further compromise of the system and network.

## Impact

Successful exploitation of CVE-2026-24893 allows attackers to execute arbitrary operating system commands on the openITCOCKPIT server. This could lead to complete system compromise, data exfiltration, and potentially lateral movement within the network. The vulnerability affects all installations of openITCOCKPIT Community Edition prior to version 5.5.2. Organizations relying on openITCOCKPIT for critical infrastructure monitoring are at significant risk of disruption and data loss.

## Recommendation

*   Immediately upgrade openITCOCKPIT to version 5.5.2 or later to patch CVE-2026-24893.
*   Implement the Sigma rule `openitcockpit_command_injection_process` to detect potential exploitation attempts by monitoring process creation events.
*   Review and restrict user permissions within openITCOCKPIT to limit the number of accounts capable of modifying host configurations.
*   Deploy the Sigma rule `openitcockpit_command_injection_web` and tune for your environment to detect possible command injection attempts through web server logs.
