---
title: DIRAC Vulnerable to Remote Code Execution via eval on Untrusted Input in RequestManager
slug: 2026-07-dirac-rce-requestmanager
description: A critical remote code execution vulnerability (CVE-2026-45579) in DIRAC's RequestManager allows any authenticated user to execute arbitrary commands or code on the DIRAC server due to the improper use of `eval()` on untrusted input, leading to full system compromise including data exfiltration and log manipulation.
date: "2026-07-13T17:23:02Z"
lastmod: "2026-07-13T18:43:03Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - RCE
  - python
  - web-application
  - vulnerability
  - sql-injection
  - access-control
vendors:
  - DIRACGrid
products:
  - DIRAC (>= 6, < 8.0.79)
  - DIRAC (>= 8.1.0a1, < 9.0.22)
  - DIRAC (>= 9.1.0, < 9.1.10)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An remote code execution vulnerability exists in RequestManager due to the use of eval on untrusted input that allows any authenticated user to run code/commands on the DIRAC server as the system user running the DIRAC services.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A number of the functions in PilotManager pass parameters directly through to the database layer, which then does not do any escaping on the parameters.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: This allows any user to manage (e.g. delete, read output of) any pilot pilot job
    confidence_band: low
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: a carefully crafted set of parameters containing SQL escapes would likely be able to change or return other database entries.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Data Manipulation
    evidence: a carefully crafted set of parameters containing SQL escapes would likely be able to change or return other database entries.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1491
    technique_name: Defacement
    evidence: This allows any user to manage (e.g. delete, read output of) any pilot pilot job
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-9jpv-c7p4-997x
  - https://github.com/advisories/GHSA-7xw9-549r-8jrc
rules:
  - title: Detects CVE-2026-45579 Exploitation - DIRAC RequestManager RCE
    description: Detects CVE-2026-45579 exploitation - HTTP requests targeting the export_getRequestCountersWeb function with suspicious characters in groupingAttribute indicating remote code execution via eval on untrusted input.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059
      - T1059.006
    data_sources:
      - webserver
  - title: Detect DIRAC PilotManager SQL Injection Attempts
    description: Detects suspicious patterns indicative of SQL injection attempts against the DIRAC PilotManager service, targeting vulnerable functions identified in GHSA-7xw9-549r-8jrc.
    platform: sigma
    severity: high
    tactics:
      - collection
      - impact
      - initial_access
    techniques:
      - T1005
      - T1190
      - T1499
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-07-13T18:43:03Z"
    level: L2
    summary: 'added detection rule: Detect DIRAC PilotManager SQL Injection Attempts'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-7xw9-549r-8jrc
---

A critical remote code execution vulnerability, tracked as CVE-2026-45579, has been identified in the DIRAC RequestManager component. This flaw stems from the `export_getRequestCountersWeb` function, which is accessible to any authenticated user and processes untrusted input in its `groupingAttribute` parameter. This parameter is then prepended with "Request." and directly passed to an `eval()` call within `RequestDB.py` if the attribute is unrecognized. This allows an authenticated attacker to inject and execute arbitrary Python code on the DIRAC server. Successful exploitation grants the attacker the ability to run commands as the system user running DIRAC services, enabling full control over the system, including access to sensitive configuration files like `dirac.cfg`, database passwords, proxies, and tokens. Attackers could also remove their exploit evidence from local RequestManager logs.

## Attack Chain

1. An authenticated attacker accesses the DIRAC web interface or API.
2. The attacker identifies the `export_getRequestCountersWeb` function within the RequestManager as an accessible endpoint.
3. A specially crafted HTTP request is sent to invoke this function, including a malicious `groupingAttribute` parameter.
4. The `groupingAttribute` parameter contains Python code designed for arbitrary command execution (e.g., `__import__('os').system('id')`) leveraging dunder methods to access system functions.
5. The `ReqManagerHandler.py` component passes the untrusted `groupingAttribute` value to the `RequestDB` database instance.
6. Within `RequestDB.py`, if the provided `groupingAttribute` is not a recognized grouping string, the system prepends "Request." to it and executes the resulting string via an `eval()` call.
7. The `eval()` function executes the attacker's injected Python code with the privileges of the system user running the DIRAC services.
8. The attacker achieves remote code execution, enabling actions such as retrieving sensitive `dirac.cfg` contents, exfiltrating database passwords and tokens, or removing forensic evidence from local RequestManager logs.

## Impact

Successful exploitation of CVE-2026-45579 allows any authenticated user to gain arbitrary code execution on the DIRAC server, running commands as the system user. This leads to a full compromise of the DIRAC system, granting the attacker access to highly sensitive information such as the `dirac.cfg` file, database passwords, and all stored proxies and tokens. The attacker could also utilize this access to manipulate or remove local log files, hindering incident response and forensic analysis efforts. The scope of impact is broad, encompassing data theft, privilege escalation, and complete control over the compromised DIRAC infrastructure.

## Recommendation

* Deploy the Sigma rule "Detects CVE-2026-45579 Exploitation - DIRAC RequestManager RCE" to your SIEM system to identify exploitation attempts.
* Ensure web server access logs are comprehensively collected and stored, providing the necessary `cs-uri-stem` and `cs-uri-query` fields for the detection rule.
* Immediately apply the patches to DIRAC versions 8.0.79, 9.0.22, or 9.1.10 as recommended in the advisory to mitigate CVE-2026-45579.
* Implement rigorous authentication and authorization policies for all users accessing DIRAC systems to reduce the attack surface.
