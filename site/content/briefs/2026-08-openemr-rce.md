---
title: Remote Code Execution in OpenEMR Document Category Tree
slug: 2026-08-openemr-rce
description: OpenEMR versions 8.2.0 and earlier are vulnerable to authenticated remote code execution via SQL injection and unsafe eval() calls in the document category tree component.
date: "2026-08-03T18:05:37Z"
lastmod: "2026-08-03T18:06:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application-vulnerability
  - remote-code-execution
  - healthcare
  - cve-2026-39931
  - sql-injection
  - web-application
vendors:
  - OpenEMR
products:
  - OpenEMR (8.2.0)
  - OpenEMR (<= 8.2.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: The vulnerability allows an authenticated administrator to execute arbitrary operating system commands by injecting PHP payloads.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: The injection of PHP code into the database and its execution via eval() effectively creates a persistent, database-backed web shell mechanism.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The execution of payloads via unauthenticated pages allows an attacker to escalate access beyond administrative boundaries into system-level code execution.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: OpenEMR through 8.2.0 contains an authenticated SQL injection vulnerability in the backup configuration import feature.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can exploit the unfiltered shell_exec invocation of the mysql command-line client to execute commands.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.002
    technique_name: 'Server Software Component: SQL Stored Procedures'
    evidence: Attackers can inject backdoor accounts, create persistent triggers or stored procedures.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can register an OAuth2 client via the unauthenticated registration endpoint and use the password grant to exchange credentials for an API access token, bypassing the normal web interface authentication.
    confidence_band: high
cves:
  - id: CVE-2026-39932
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39932
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39931
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67611
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade OpenEMR to the latest patched version to remediate CVE-2026-39932.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-39932
  mitigation_plan:
    - priority: immediate
      action: Restrict administrative access to the web interface to authorized IP addresses.
      owner: IT Operations
      addresses: CVE-2026-39932
      evidence: Exploit requires administrative access.
updates:
  - at: "2026-08-03T18:06:26Z"
    level: L2
    summary: 'merged source coverage: Authenticated SQL Injection in OpenEMR Backup Configuration'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-39931
  - at: "2026-08-03T18:06:46Z"
    level: L2
    summary: 'merged source coverage: Authentication Bypass in OpenEMR OAuth2 Implementation'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67611
---

OpenEMR versions up to and including 8.2.0 contain a critical remote code execution vulnerability located within the document category tree component, specifically in the library/classes/Tree.class.php file. The vulnerability stems from an insecure implementation that allows an authenticated administrator to inject arbitrary PHP payloads into the categories database table. By leveraging SQL injection to alter the id column type to VARCHAR, an attacker can insert a malicious payload. This payload is subsequently executed via an unsanitized eval() function call whenever the CategoryTree component is instantiated. Because this component is used across various parts of the application, including pages accessible to unauthenticated users or those with low privileges, a successful exploit results in arbitrary command execution under the context of the web server user. This vulnerability requires administrative access to initiate, but the impact extends to full system compromise from the web server's privilege level.

## Attack Chain

1. Attacker authenticates to the OpenEMR instance with administrative privileges.
2. Attacker interacts with the document category tree management interface.
3. Attacker executes a crafted SQL injection payload to alter the schema of the categories database table, changing the id column type to VARCHAR.
4. Attacker inserts a malicious PHP code snippet as a record into the categories table.
5. Attacker triggers the vulnerability by navigating to a page (including unauthenticated endpoints) that invokes the CategoryTree class.
6. The application performs an unsanitized eval() call on the injected database content.
7. The web server process executes the attacker-supplied PHP payload.
8. Attacker achieves remote code execution as the web server user for further post-exploitation activity.

## Impact

Successful exploitation allows for full remote command execution on the host running the OpenEMR instance. This compromises the integrity and confidentiality of the electronic medical records data stored within the application and grants the attacker a foothold on the internal network segment hosting the web server.

## Recommendation

1. Upgrade all OpenEMR instances to the latest secure version addressing this vulnerability.
2. Implement strict administrative access controls to limit the number of users capable of modifying database-driven configurations.
3. Monitor web server logs for suspicious database query patterns, specifically those attempting to alter schema definitions or modify core application tables.
4. Perform code review or implement file integrity monitoring on library/classes/Tree.class.php to detect unauthorized modifications.
