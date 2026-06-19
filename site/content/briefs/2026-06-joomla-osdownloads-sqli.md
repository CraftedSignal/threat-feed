---
title: Joomla OSDownloads SQL Injection (CVE-2017-20259)
slug: 2026-06-joomla-osdownloads-sqli
description: An unauthenticated SQL injection vulnerability (CVE-2017-20259) in Joomla OSDownloads version 1.7.4 allows attackers to execute arbitrary SQL queries via a crafted GET request to index.php, extracting sensitive database information like credentials and configuration data.
date: "2026-06-19T16:29:39Z"
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
vendors:
  - Joomlashack
products:
  - OSDownloads 1.7.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: ""
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
cves:
  - id: CVE-2017-20259
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20259
  - https://extensions.joomla.org/extensions/extension/directory-a-documentation/downloads/osdownloads/
  - https://joomlashack.com/
  - https://www.exploit-db.com/exploits/42561
  - https://www.vulncheck.com/advisories/joomla-osdownloads-sql-injection-via-item-view
rules:
  - title: Detects CVE-2017-20259 Exploitation - Joomla OSDownloads SQLi
    description: Detects exploitation attempts against CVE-2017-20259, an unauthenticated SQL injection in Joomla OSDownloads 1.7.4, identified by specific query parameters and SQL injection keywords.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
      - T1190
    data_sources:
      - webserver
  - title: Detect Generic SQL Injection Indicators in Web Requests
    description: Detects common SQL injection indicators present in web server access logs, useful for identifying broader SQLi attempts against web applications.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Joomla OSDownloads version 1.7.4 is affected by a critical SQL injection vulnerability, tracked as CVE-2017-20259. This flaw allows unauthenticated attackers to execute arbitrary SQL queries against the underlying database. Exploitation involves sending a specially crafted HTTP GET request to `index.php` with the `option=com_osdownloads&view=item&id=[SQL]` parameters, where malicious SQL code is injected into the `id` parameter. This vulnerability, disclosed in 2017 but recently published by NVD, poses a significant risk as it enables attackers to extract sensitive database information, including user credentials, configuration settings, and other proprietary data, leading to potential data breaches and further system compromise. The high CVSS score reflects the ease of exploitation and severe impact.

## Attack Chain

1. An unauthenticated attacker identifies a public-facing Joomla installation running a vulnerable version (1.7.4) of the OSDownloads component.
2. The attacker crafts a malicious HTTP GET request targeting the `index.php` endpoint of the Joomla application.
3. The crafted request includes specific query parameters: `option=com_osdownloads` and `view=item`.
4. Malicious SQL code, designed for injection, is appended to the `id` parameter within the GET request (e.g., `id=1 UNION SELECT ...`).
5. The vulnerable Joomla OSDownloads component processes the request without properly sanitizing the `id` parameter, leading to the execution of the injected SQL query on the backend database.
6. The attacker iterates on the injected queries to extract sensitive database schema information, such as table names and column structures, and then specific data.
7. Confidential data, including user credentials, API keys, and system configuration details, is retrieved from the database and returned in the HTTP response body.
8. This exfiltrated information can then be leveraged by the attacker to gain unauthorized administrative access to the Joomla application or other connected systems, leading to further compromise.

## Impact

Successful exploitation of CVE-2017-20259 allows unauthenticated attackers to compromise the confidentiality and integrity of the Joomla application's database. Attackers can extract highly sensitive information, such as administrator credentials, user data, and system configuration details. This data can then be used to gain unauthorized access to the Joomla backend, deface the website, inject malicious content, or pivot to other systems within the network. The exfiltration of user credentials or proprietary business data can lead to severe reputational damage, financial losses, and regulatory non-compliance for affected organizations.

## Recommendation

*   Patch Joomla OSDownloads to a version greater than 1.7.4 immediately to remediate CVE-2017-20259.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect exploitation attempts against CVE-2017-20259.
*   Enable comprehensive web server access logging to capture full HTTP request details, including query parameters, to facilitate detection of SQL injection attempts.
*   Implement a Web Application Firewall (WAF) to filter and block malicious SQL injection patterns in incoming HTTP requests.
