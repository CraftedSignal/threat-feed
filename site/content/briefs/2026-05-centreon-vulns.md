---
title: Multiple Vulnerabilities in Centreon Products
slug: 2026-05-centreon-vulns
description: Multiple vulnerabilities in Centreon products allow for remote code execution, SQL injection, and cross-site scripting.
date: "2026-05-12T14:14:28Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - centreon
  - vulnerability
  - rce
  - sqli
  - xss
vendors:
  - Centreon
products:
  - Anomaly Detection
  - Auto Discovery
  - AWIE
  - BAM
  - DSM
  - License Manager
  - MAP
  - MBI
  - Open Tickets
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0572/
  - https://thewatch.centreon.com/latest-security-bulletins-64/april-2026-monthly-security-bulletin-for-centreon-infra-monitoring-high-5660
iocs:
  - type: url
    value: https://thewatch.centreon.com/latest-security-bulletins-64/april-2026-monthly-security-bulletin-for-centreon-infra-monitoring-high-5660
ioc_counts:
  url: 1
rules:
  - title: Detect Suspicious URI Access to Centreon Web Interface
    description: Detects suspicious URI access patterns to the Centreon web interface, potentially indicating vulnerability scanning or exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SQL Injection Attempts in Centreon Web Interface
    description: Detects SQL injection attempts by identifying SQL keywords in URI queries
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities have been discovered in Centreon products, potentially allowing attackers to perform malicious actions. These vulnerabilities, disclosed in the April 2026 monthly security bulletin, include remote code execution (RCE), SQL injection (SQLi), and cross-site scripting (XSS). Exploitation of these flaws could lead to complete system compromise. The affected products include various modules such as Anomaly Detection, Auto Discovery, AWIE, BAM, DSM, License Manager, MAP, MBI, and Open Tickets. Successful exploitation of these vulnerabilities allows an attacker to execute arbitrary code remotely, inject malicious SQL queries, and inject malicious scripts into web pages viewed by other users.

## Attack Chain

1.  Attacker identifies a vulnerable Centreon product exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting a specific vulnerable endpoint in one of the affected Centreon modules (e.g., Anomaly Detection, Auto Discovery).
3.  If exploiting the SQL injection vulnerability, the attacker injects malicious SQL code into a parameter within the HTTP request.
4.  The Centreon application processes the malicious SQL code, allowing the attacker to read, modify, or delete data from the database.
5.  If exploiting the XSS vulnerability, the attacker injects malicious JavaScript code into a field that is displayed to other users.
6.  When another user views the page containing the injected JavaScript, the code executes in their browser, potentially stealing credentials or performing other malicious actions.
7.  If exploiting the RCE vulnerability, the attacker injects code that allows arbitrary command execution.
8.  The attacker executes commands to gain a reverse shell, install malware, or further compromise the system.

## Impact

Successful exploitation of these vulnerabilities can have severe consequences. An attacker could gain complete control of the Centreon system, leading to data breaches, service disruption, and further compromise of the network. Given Centreon's role in infrastructure monitoring, a successful attack could blind organizations to critical issues and allow attackers to move laterally within the network undetected.

## Recommendation

*   Apply the patches provided in the Centreon security bulletin immediately to all affected products (Anomaly Detection, Auto Discovery, AWIE, BAM, DSM, License Manager, MAP, MBI, Open Tickets).
*   Monitor web server logs for suspicious activity, such as unusual HTTP requests targeting Centreon modules (see references URL).
*   Deploy the Sigma rules provided in this brief to your SIEM and tune for your environment.
