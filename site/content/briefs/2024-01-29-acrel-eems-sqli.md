---
title: Acrel EEMS Enterprise Power Operation and Maintenance Cloud Platform SQL Injection Vulnerability
slug: 2024-01-29-acrel-eems-sqli
description: A SQL injection vulnerability exists in Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform 1.3.0 when manipulating the 'fCircuitids' argument in the '/SubstationWEBV2/main/elecMaxMinAvgValue' file, potentially allowing for remote code execution or data exfiltration.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
vendors:
  - Acrel Electrical
products:
  - EEMS Enterprise Power Operation and Maintenance Cloud Platform (1.3.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7695
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7695
rules:
  - title: Detect Suspicious fCircuitids Parameter Manipulation
    description: Detects suspicious requests to the elecMaxMinAvgValue endpoint with potentially malicious SQL injection attempts in the fCircuitids parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious URL Encoding in fCircuitids Parameter
    description: Detects suspicious URL encoded SQL injection attempts in the fCircuitids parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform version 1.3.0. The vulnerability resides within the `/SubstationWEBV2/main/elecMaxMinAvgValue` file and is triggered by manipulating the `fCircuitids` argument. This flaw allows remote attackers to inject arbitrary SQL commands, potentially leading to unauthorized data access, modification, or complete system compromise. The vendor was notified about the vulnerability but did not provide a response. Given the publicly disclosed nature of the exploit, organizations using the affected software should take immediate steps to mitigate the risk.

## Attack Chain

1.  The attacker identifies an instance of Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform 1.3.0 accessible over the network.
2.  The attacker crafts a malicious HTTP request targeting the `/SubstationWEBV2/main/elecMaxMinAvgValue` endpoint.
3.  Within the request, the attacker injects SQL code into the `fCircuitids` parameter.
4.  The application improperly sanitizes the input, passing the malicious SQL code to the database.
5.  The database executes the injected SQL code.
6.  The attacker is able to retrieve sensitive data from the database, such as user credentials or system configurations.
7.  The attacker uses the stolen credentials to gain unauthorized access to other parts of the application.
8.  The attacker gains complete control of the application server, potentially leading to further compromise of the network.

## Impact

Successful exploitation of this SQL injection vulnerability could allow attackers to access and modify sensitive data, potentially disrupting power operation and maintenance processes. Given that the software is used for enterprise power management, this could lead to significant financial losses, reputational damage, and potential safety hazards. The number of victims is currently unknown, but any organization utilizing the affected software (version 1.3.0 of Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform) is potentially at risk.

## Recommendation

*   Inspect web server logs for suspicious requests to `/SubstationWEBV2/main/elecMaxMinAvgValue` containing unusual characters or SQL keywords in the `fCircuitids` parameter to detect potential exploitation attempts.
*   Deploy the Sigma rule `Detect Suspicious fCircuitids Parameter Manipulation` to identify potentially malicious requests targeting the vulnerable endpoint.
*   Implement input validation and sanitization measures on the `fCircuitids` parameter to prevent SQL injection attacks.
*   Consider using a Web Application Firewall (WAF) to filter out malicious requests targeting the vulnerable endpoint.
