---
title: Joomla! Component JB Visa 1.0 SQL Injection (CVE-2017-20255)
slug: 2026-06-joomla-jb-visa-sqli
description: An unauthenticated SQL injection vulnerability (CVE-2017-20255) in Joomla! Component JB Visa 1.0 allows attackers to execute arbitrary SQL queries by injecting malicious code via the 'visatype' parameter in GET requests to 'index.php?option=com_bookpro&view=popup', leading to the extraction of sensitive database information including credentials.
date: "2026-06-19T16:24:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - joomla
  - web-vulnerability
  - cve
vendors:
  - Joombooking
products:
  - JB Visa 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20255
  - http://joombooking.com/
  - https://extensions.joomla.org/extensions/extension/vertical-markets/booking-a-reservations/jb-visa/
  - https://www.exploit-db.com/exploits/43350
  - https://www.vulncheck.com/advisories/joomla-component-jb-visa-sql-injection-via-visatype
rules:
  - title: Detects CVE-2017-20255 Exploitation - Joomla JB Visa SQL Injection
    description: Detects exploitation attempts for CVE-2017-20255, an unauthenticated SQL injection in Joomla! Component JB Visa 1.0, targeting the visatype parameter in specific GET requests.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1505.004
    data_sources:
      - webserver
  - title: Detect Generic SQL Injection Attempts in GET Requests
    description: Detects common patterns indicative of SQL injection attempts within URL query parameters for GET requests, useful for broader coverage beyond specific CVEs.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1505.004
    data_sources:
      - webserver
rules_count: 2
---

CVE-2017-20255 describes an unauthenticated SQL injection vulnerability present in Joomla! Component JB Visa version 1.0. This flaw allows remote attackers to execute arbitrary SQL queries, posing a significant risk to the confidentiality of underlying database contents. Attackers can exploit this by sending specially crafted HTTP GET requests to the vulnerable `index.php` endpoint, targeting specific parameters like `option=com_bookpro` and `view=popup`. By injecting malicious SQL code into the `visatype` parameter, adversaries can bypass authentication and directly interact with the database. This enables the exfiltration of sensitive information, such as user credentials and full table contents, from the compromised Joomla! installation, potentially leading to further system compromise.

## Attack Chain

1.  **Initial Access (HTTP GET Request):** An unauthenticated attacker sends an HTTP GET request to the vulnerable Joomla! instance running Component JB Visa 1.0.
2.  **Targeting Vulnerable Endpoint:** The GET request specifically targets the `/index.php` path with the URL query parameters `option=com_bookpro` and `view=popup` to access the vulnerable component.
3.  **SQL Payload Injection:** The attacker injects malicious SQL code into the `visatype` parameter within the URL query string (e.g., `visatype=%27%20OR%201=1--%20`).
4.  **Application Processing:** The Joomla! application, due to CVE-2017-20255, processes the HTTP request and incorporates the malicious `visatype` input directly into an SQL query without proper sanitization.
5.  **Database Execution:** The backend database executes the attacker's arbitrary SQL query, including the injected malicious code.
6.  **Information Exfiltration:** The executed SQL query retrieves sensitive database information, such as user credentials, hashed passwords, or entire table contents, which is then returned in the HTTP response body to the attacker.

## Impact

Successful exploitation of CVE-2017-20255 allows unauthenticated attackers to gain full access to the database underlying the Joomla! instance. This can lead to the complete compromise of sensitive organizational data, including user accounts, personal identifiable information (PII), and application-specific configurations. The exfiltration of credentials could facilitate lateral movement within the network or access to other systems. While no specific victim count or targeted sectors are provided, any organization utilizing the vulnerable Joomla! Component JB Visa 1.0 is at risk of severe data breaches and potential regulatory fines.

## Recommendation

*   **Patch CVE-2017-20255:** Immediately upgrade Joomla! Component JB Visa to a patched version or disable/remove the component if an upgrade is not available.
*   **Deploy Sigma Rules:** Deploy the provided Sigma rules "Detects CVE-2017-20255 Exploitation - Joomla JB Visa SQL Injection" and "Detect Generic SQL Injection Attempts in GET Requests" to your SIEM and tune them for your environment.
*   **Enable Webserver Logging:** Ensure comprehensive logging for HTTP requests (especially URL paths, query parameters, and methods) is enabled on your web servers to facilitate detection of the patterns used in the Sigma rules.
