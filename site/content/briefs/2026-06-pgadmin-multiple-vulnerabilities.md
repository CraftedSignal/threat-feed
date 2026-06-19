---
title: 'pgAdmin: Multiple Vulnerabilities Lead to RCE, SQLi, XSS'
slug: 2026-06-pgadmin-multiple-vulnerabilities
description: A remote, authenticated attacker can exploit multiple vulnerabilities in pgAdmin to achieve arbitrary code execution with user or administrator privileges, bypass security measures, perform SQL Injection and Cross-Site Scripting attacks, redirect users to malicious websites, disclose sensitive information, and manipulate data. This comprehensive set of capabilities allows for significant compromise of system integrity, confidentiality, and potentially availability, posing a high risk to affected environments.
date: "2026-06-19T09:23:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - pgadmin
  - vulnerability
  - web-application
  - rce
  - sql-injection
  - xss
vendors:
  - pgAdmin
products:
  - pgAdmin
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2005
rules:
  - title: Detect SQL Injection in pgAdmin Web Requests
    description: Detects common SQL Injection patterns in cs-uri-query or cs-uri-stem targeting pgAdmin, indicating attempts to manipulate database queries.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.008
      - T1190
    data_sources:
      - webserver
  - title: Detect XSS Attempts in pgAdmin Web Requests
    description: Detects common Cross-Site Scripting (XSS) payload patterns in cs-uri-query or cs-uri-stem targeting pgAdmin, indicating attempts to inject malicious client-side scripts.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.007
      - T1190
    data_sources:
      - webserver
  - title: Detect Command Injection in pgAdmin Web Requests
    description: Detects patterns indicative of command injection attempts via web request parameters, often using shell metacharacters to execute arbitrary commands on the server.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 3
---

A remote, authenticated attacker can leverage multiple vulnerabilities within pgAdmin to gain significant control and access to affected systems. This advisory from BSI CERT-Bund, published on 2026-06-19, highlights a high-severity threat where an attacker, having obtained initial access through legitimate authentication, can exploit weaknesses to achieve arbitrary code execution with user or administrator privileges. The vulnerabilities also permit bypassing security mechanisms, performing SQL Injection and Cross-Site Scripting (XSS) attacks, redirecting users to malicious websites, disclosing sensitive information, and manipulating data. This broad range of capabilities poses a critical risk to the integrity, confidentiality, and availability of data and systems managed by pgAdmin instances across Windows, Linux, and macOS platforms.

## Attack Chain

1. Initial Access / Authentication: Attacker gains legitimate authenticated access to the pgAdmin web interface, potentially via compromised credentials or other means not detailed.
2. Vulnerability Identification: Attacker identifies and targets specific web application vulnerabilities within the pgAdmin interface (e.g., SQL Injection points, XSS input fields, or command injection flaws).
3. Security Bypass: Exploits vulnerabilities to bypass existing security measures, such as input sanitization or access controls, often leveraging SQLi or path traversal.
4. Code Execution (SQLi/XSS/RCE): Leverages specific vulnerabilities (e.g., SQL Injection, Cross-Site Scripting, or a direct Remote Code Execution flaw) to inject and execute malicious code or commands.
5. Privilege Escalation: If initial code execution is at a lower privilege, the attacker exploits further vulnerabilities to escalate privileges to user or administrator level on the underlying system.
6. Data Manipulation/Disclosure: With elevated privileges or direct access, the attacker manipulates existing data, deletes critical information, or exfiltrates sensitive data from the database.
7. Impact on Users (XSS/Redirection): Through Cross-Site Scripting (XSS), the attacker may redirect legitimate pgAdmin users to malicious external websites or harvest their credentials.
8. System Compromise: Ultimately leads to full compromise of the pgAdmin server and potentially connected database systems, allowing for further lateral movement or persistent access.

## Impact

The successful exploitation of these vulnerabilities can lead to severe consequences, including full system compromise and loss of data integrity and confidentiality. Attackers can execute arbitrary code, potentially leading to the deployment of malware, ransomware, or backdoors. The ability to perform SQL Injection allows direct manipulation or exfiltration of database contents. Cross-Site Scripting can compromise user sessions and redirect legitimate users to phishing sites. Data manipulation can corrupt critical business information, while sensitive information disclosure can expose proprietary data, intellectual property, or personal identifiable information (PII). While no specific victim counts or sectors are mentioned in the advisory, any organization utilizing pgAdmin across Windows, Linux, or macOS could be at high risk.

## Recommendation

* Immediately apply all available security updates for pgAdmin to address the multiple identified vulnerabilities, as detailed in the BSI CERT-Bund advisory WID-SEC-2026-2005.
* Deploy the provided Sigma rules for webserver logs (Detect SQL Injection in pgAdmin Web Requests, Detect XSS Attempts in pgAdmin Web Requests, Detect Command Injection in pgAdmin Web Requests) to your SIEM solution to detect attempted exploitation of these vulnerabilities.
* Enable comprehensive webserver access logging for all pgAdmin instances to capture `cs-uri-stem`, `cs-uri-query`, and `cs-method` for forensic analysis and detection.
* Implement strict access controls and monitor all authenticated access to pgAdmin for anomalous behavior, especially attempts to modify configurations or execute unusual commands.
