---
title: Acrel ECEMS SQL Injection Vulnerability
slug: 2026-05-acrel-sql-injection
description: A SQL injection vulnerability in Acrel Electrical ECEMS Enterprise Microgrid Energy Efficiency Management System 1.3.0 allows remote attackers to execute arbitrary SQL commands by manipulating the 'fCircuitids' argument in the '/SubstationWEBV2/main/elecMaxMinAvgValue' file.
date: "2026-05-03T12:15:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-7694
  - webserver
vendors:
  - Acrel Electrical
products:
  - ECEMS Enterprise Microgrid Energy Efficiency Management System 1.3.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7694
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7694
  - https://ucn9h68n9289.feishu.cn/wiki/WZMewApmsiT3PMkCJfzcASEznOb
  - https://vuldb.com/submit/803271
  - https://vuldb.com/vuln/360863
  - https://vuldb.com/vuln/360863/cti
rules:
  - title: Detect Acrel ECEMS SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the Acrel ECEMS application by monitoring HTTP requests to the vulnerable endpoint and looking for common SQL injection payloads in the 'fCircuitids' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages
    description: Detects common SQL injection error messages in web server logs, which can indicate successful or attempted SQL injection attacks.
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

Acrel Electrical's ECEMS Enterprise Microgrid Energy Efficiency Management System version 1.3.0 is vulnerable to SQL injection. The vulnerability resides in the `/SubstationWEBV2/main/elecMaxMinAvgValue` file, where manipulation of the `fCircuitids` argument allows for the injection of arbitrary SQL commands. The vulnerability, identified as CVE-2026-7694, can be exploited remotely without authentication, posing a significant risk to systems exposed to the network. The vendor was notified but did not respond, and a public exploit is available, increasing the likelihood of exploitation. This flaw allows attackers to potentially access, modify, or delete sensitive data within the ECEMS database.

## Attack Chain

1.  Attacker identifies an accessible instance of Acrel ECEMS 1.3.0.
2.  Attacker crafts a malicious SQL payload designed to extract sensitive information or modify the database.
3.  The attacker sends a crafted HTTP request to `/SubstationWEBV2/main/elecMaxMinAvgValue` with the SQL payload embedded in the `fCircuitids` parameter.
4.  The ECEMS application fails to properly sanitize the `fCircuitids` input.
5.  The application executes the attacker-supplied SQL query against the database.
6.  The database server processes the malicious query, potentially returning sensitive data or executing harmful commands.
7.  The attacker receives the output of the injected SQL query.
8.  The attacker uses the extracted information for further malicious activities, such as data exfiltration, privilege escalation, or denial of service.

## Impact

Successful exploitation of this SQL injection vulnerability could allow an attacker to read sensitive information from the ECEMS database, modify existing data, or even gain administrative access to the system. This could lead to the compromise of energy efficiency management data, potentially impacting grid stability and financial records. Given the lack of vendor response and the availability of a public exploit, organizations using the affected software are at high risk. The impact includes potential data breaches, system outages, and reputational damage.

## Recommendation

*   Inspect web server logs for suspicious requests to `/SubstationWEBV2/main/elecMaxMinAvgValue` containing potentially malicious SQL syntax within the `fCircuitids` parameter (see Sigma rule "Detect Acrel ECEMS SQL Injection Attempt").
*   Deploy the Sigma rule "Detect SQL Injection Error Messages" to identify potential SQL injection attempts across all web applications.
*   Apply input validation and sanitization to all user-supplied input, especially the `fCircuitids` parameter in `/SubstationWEBV2/main/elecMaxMinAvgValue`, to prevent SQL injection.
*   Consider deploying a web application firewall (WAF) to filter out malicious requests targeting this vulnerability.
