---
title: Frappe Framework ERPNext 13.4.0 Sandbox Escape Vulnerability
slug: 2024-01-03-frappe-rce
description: Frappe Framework ERPNext 13.4.0 contains a sandbox escape vulnerability allowing authenticated users with System Manager role to execute arbitrary code via frame introspection and `os.popen`.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sandbox-escape
  - rce
  - erpnext
vendors:
  - Frappe
products:
  - ERPNext
  - Frappe Framework 13.4.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2023-54345
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54345
  - https://www.vulncheck.com/advisories/frappe-framework-erpnext-remote-code-execution
rules:
  - title: Detect os.popen in ERPNext Server Scripts
    description: Detects the use of os.popen within ERPNext server scripts, indicating a potential sandbox escape attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
  - title: Suspicious Process Execution by ERPNext User
    description: Detects suspicious processes being spawned by the ERPNext application user, potentially indicating RCE.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Frappe Framework is an open-source web application framework, and ERPNext is an ERP system built on top of it. A critical vulnerability, CVE-2023-54345, exists in Frappe Framework ERPNext version 13.4.0 related to a sandbox escape in the RestrictedPython environment. This allows authenticated users with the System Manager role to bypass intended security restrictions and execute arbitrary code on the server. The vulnerability is rooted in the improper handling of frame introspection within RestrictedPython, enabling attackers to traverse the call stack and invoke dangerous functions like `os.popen`. Exploitation involves crafting malicious server-side scripts through the `/app/server-script` endpoint. Successful exploitation leads to complete server compromise.

## Attack Chain

1.  An attacker authenticates to the ERPNext system with a System Manager role.
2.  The attacker creates a new server script via the `/app/server-script` endpoint.
3.  The attacker crafts a malicious Python script designed to exploit the RestrictedPython sandbox.
4.  The malicious script uses frame introspection to access the `gi_frame` attribute, allowing traversal of the call stack.
5.  The script invokes `os.popen` (or a similar function) to execute arbitrary system commands.
6.  The server executes the attacker-supplied commands with the privileges of the ERPNext application user.
7.  The attacker gains control over the server, potentially installing malware, exfiltrating data, or causing denial of service.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on the server hosting the Frappe Framework ERPNext application. This can lead to full system compromise, data breaches, and denial of service. The vulnerability affects version 13.4.0 of ERPNext. If successfully exploited, threat actors can leverage the compromised system to pivot to other internal resources.

## Recommendation

*   Apply available patches or upgrade to a patched version of Frappe Framework ERPNext to address CVE-2023-54345.
*   Monitor web server logs for unusual activity related to the `/app/server-script` endpoint.
*   Implement the provided Sigma rule to detect potential exploitation attempts based on `os.popen` usage within server scripts.
*   Review and restrict the permissions of the System Manager role to minimize the attack surface.
*   Deploy the second Sigma rule to detect suspicious process execution initiated by the ERPNext application user.
