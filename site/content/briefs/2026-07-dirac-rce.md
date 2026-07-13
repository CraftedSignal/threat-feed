---
title: DIRAC Vulnerable to Remote Code Execution via SQL Injection and Eval in DatasetManager
slug: 2026-07-dirac-rce
description: An authenticated user can achieve remote code execution in DIRAC's FileCatalog DatasetManager due to an SQL injection vulnerability (CVE-2026-61667) that allows manipulation of query results passed to an `eval` function, leading to full system compromise.
date: "2026-07-13T18:41:36Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - sql-injection
  - python
  - web-application
  - vulnerability
  - cve-2026-61667
vendors:
  - DIRACGrid
products:
  - DIRAC
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The result (which is user controllable due to the SQL injection) is passed into eval almost immediately on return, leading to code execution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This allows any authenticated user to run commands on the server, which allows a full compromise of the DIRAC system.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: If local logging is used, they can also remove evidence of the exploit from the log.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: they can read the local dirac.cfg, get database passwords and export all stored proxies and tokens.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: they can read the local dirac.cfg, get database passwords and export all stored proxies and tokens.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: they can read the local dirac.cfg
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-m4m7-4cw8-62j6
  - https://pypi.org/project/DIRAC/8.0.79/
  - https://pypi.org/project/DIRAC/9.0.22/
  - https://pypi.org/project/DIRAC/9.1.10/
---

A critical remote code execution vulnerability, tracked as CVE-2026-61667, has been identified in DIRAC's FileCatalog DatasetManager. This vulnerability allows an authenticated user to execute arbitrary code on the server by combining an SQL injection flaw with the improper use of Python's `eval` function. Specifically, the `checkDataset` function in `FileCatalogHandler.py` passes user-controlled input directly into an SQL query without proper escaping, leading to injection. The malicious SQL injection can manipulate the database query's result, which is subsequently passed to `eval` in `DatasetManager.py`, granting an attacker full control over the system. This allows for reading sensitive configuration files, exfiltrating database passwords, and compromising stored proxies and tokens, with the potential to also erase exploit evidence from logs. Patched versions are available for DIRAC 8.0.79, 9.0.22, and 9.1.10.

## Attack Chain

1. An authenticated attacker initiates a request to the DIRAC system, targeting the `FileCatalog.checkDataset` function.
2. The attacker crafts a malicious `datasets` argument containing an SQL injection payload and sends it to the backend database handler.
3. The `__checkDataset` function in `DatasetManager.py` constructs an SQL query using an f-string with the unescaped, user-controlled `datasets` argument, creating an SQL injection vulnerability.
4. The injected SQL payload is designed to manipulate the query's result set, inserting arbitrary Python code that the attacker wishes to execute.
5. The database executes the modified query and returns the manipulated result, which now contains the attacker's arbitrary Python code.
6. The `DatasetManager.py` module immediately passes this returned, attacker-controlled result to Python's `eval` function.
7. The `eval` function executes the attacker's arbitrary Python code with the privileges of the DIRAC application.
8. Remote code execution is achieved, allowing the attacker to perform actions such as reading `dirac.cfg`, exfiltrating database credentials, and deleting log evidence.

## Impact

Successful exploitation of CVE-2026-61667 grants any authenticated user the ability to execute arbitrary commands on the DIRAC server, leading to a complete compromise of the system. Attackers can read sensitive configuration files like `dirac.cfg`, extract database passwords, and exfiltrate all stored proxies and tokens, thereby gaining extensive access to the environment. Furthermore, if local logging is employed, the attacker can leverage this RCE to remove evidence of their activities, hindering incident response and forensic investigations. The vulnerability affects multiple versions of DIRAC, specifically versions from 6 up to 8.0.79, 8.1.0a1 up to 9.0.22, and 9.1.0 up to 9.1.10.

## Recommendation

* Immediately update all affected DIRAC installations to a patched version (8.0.79, 9.0.22, or 9.1.10) as listed in the advisory to remediate CVE-2026-61667.
* Ensure proper input validation and parameterized queries are implemented for all database interactions within applications to prevent similar SQL injection vulnerabilities.
* Implement robust logging and monitoring for critical application functions and ensure logs are forwarded to a secure, immutable log management system to prevent tampering, as attackers can remove evidence if local logging is used.
