---
title: Joomla! Component RPC Responsive Portfolio 1.6.1 SQL Injection (CVE-2017-20258)
slug: 2026-06-joomla-rpc-sql-injection
description: Unauthenticated attackers can exploit an SQL injection vulnerability (CVE-2017-20258) in Joomla! Component RPC Responsive Portfolio 1.6.1 by injecting malicious code through the 'id' parameter in GET requests, allowing the execution of arbitrary SQL queries and extraction of sensitive database information.
date: "2026-06-19T16:28:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-vulnerability
  - joomla
  - cve
  - data-exfiltration
vendors:
  - Extro
products:
  - RPC Responsive Portfolio 1.6.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
cves:
  - id: CVE-2017-20258
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20258
  - https://extensions.joomla.org/extension/rpc-responsive-portfolio/
  - https://extro.media/
  - https://www.exploit-db.com/exploits/42564
  - https://www.vulncheck.com/advisories/joomla-component-rpc-responsive-portfolio-sql-injection
rules:
  - title: Detect CVE-2017-20258 Joomla! SQL Injection Attempt
    description: Detects CVE-2017-20258 exploitation — Unauthenticated SQL injection attempt against Joomla! Component RPC Responsive Portfolio via malicious 'id' parameter in GET request to `index.php`.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1584.004
    data_sources:
      - webserver
rules_count: 1
---

A critical SQL injection vulnerability, identified as CVE-2017-20258, affects Joomla! Component RPC Responsive Portfolio version 1.6.1. This flaw enables unauthenticated attackers to execute arbitrary SQL queries against the backend database. By crafting specific HTTP GET requests to `index.php`, incorporating `option=com_pofos&view=pofo` along with malicious SQL payloads injected into the `id` parameter, threat actors can bypass authentication mechanisms. This exploitation allows for the unauthorized extraction of sensitive information, such as user credentials, system configurations, or proprietary data, posing a severe data breach risk. The vulnerability, first published on June 19, 2026, impacts all organizations utilizing the specified version of this Joomla! component.

## Attack Chain

1. An unauthenticated attacker identifies a public-facing web server hosting Joomla! and the vulnerable RPC Responsive Portfolio component version 1.6.1.
2. The attacker crafts an HTTP GET request targeting the `index.php` path, specifying the vulnerable component parameters: `option=com_pofos` and `view=pofo`.
3. A crafted SQL injection payload, such as `id=' OR 1=1--` or similar data exfiltration statements, is embedded within the `id` parameter of the GET request.
4. The web server receives the request and forwards it to the Joomla! application, which processes the RPC Responsive Portfolio component's logic.
5. Due to improper input validation, the vulnerable component concatenates the malicious `id` parameter value directly into an SQL query executed against the application's database.
6. The database executes the attacker-controlled SQL query, resulting in the retrieval of sensitive information beyond what is authorized for unauthenticated access.
7. The Joomla! application's HTTP response includes the results of the executed SQL query, returning the exfiltrated sensitive data to the attacker.
8. The attacker then parses the received HTTP response to collect and analyze the confidential database information, achieving their objective of unauthorized data disclosure.

## Impact

Successful exploitation of CVE-2017-20258 can lead to a severe data breach, compromising the confidentiality of an organization's database. Attackers can extract various forms of sensitive information, including user account details, passwords, proprietary business data, and internal system configurations. Such exfiltration can result in significant financial losses from regulatory penalties and remediation efforts, severe damage to reputation, and potential for further downstream attacks leveraging the stolen data. While specific victim numbers or affected sectors are not detailed in the advisory, any entity running the vulnerable Joomla! component is exposed to these critical risks.

## Recommendation

*   Prioritize patching or upgrading the Joomla! Component RPC Responsive Portfolio to a version that remediates CVE-2017-20258 immediately upon availability.
*   Deploy the provided Sigma rule "Detect CVE-2017-20258 Joomla! SQL Injection Attempt" to your SIEM/detection platform to identify and alert on attempted exploitation.
*   Implement or strengthen Web Application Firewall (WAF) policies to detect and block common SQL injection patterns, specifically targeting the `id` parameter in requests to `index.php?option=com_pofos&view=pofo`.
*   Regularly review web server access logs for suspicious requests matching the URL pattern `index.php?option=com_pofos&view=pofo&id=[SQL]` as identified in the IOCs section.
