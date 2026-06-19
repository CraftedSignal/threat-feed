---
title: Joomla! Calendar Planner 1.0.1 SQL Injection (CVE-2017-20267)
slug: 2026-06-joomla-calendar-planner-sqli
description: An unauthenticated attacker can exploit CVE-2017-20267, an SQL injection vulnerability in Joomla! Component Calendar Planner 1.0.1, by sending malicious GET requests to the 'events' view via the 'category_id' parameter, allowing for sensitive database information extraction.
date: "2026-06-19T16:38:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - web-vulnerability
  - joomla
  - cve
vendors:
  - Joomlathat
products:
  - Calendar Planner 1.0.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2017-20267
  - http://joomlathat.com/
  - https://extensions.joomla.org/extensions/extension/calendars-a-events/events/calendar-planner/
  - https://www.exploit-db.com/exploits/42501
  - https://www.vulncheck.com/advisories/joomla-component-calendar-planner-sql-injection
rules:
  - title: Detects CVE-2017-20267 Exploitation — SQLi in Calendar Planner
    description: Detects CVE-2017-20267 exploitation by identifying common SQL injection patterns in GET requests targeting the 'category_id' parameter of the Joomla! Calendar Planner component's 'events' view.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2017-20267 details a critical SQL injection vulnerability present in Joomla! Component Calendar Planner version 1.0.1. This flaw allows unauthenticated attackers to inject arbitrary SQL commands into the backend database. By crafting malicious GET requests that target the 'events' view and manipulate the 'category_id' parameter, attackers can force the application to execute their SQL queries. The primary impact of successful exploitation is the extraction of sensitive information directly from the database, potentially including user credentials, personal data, or other confidential business records. While this CVE was published in 2026, it references a vulnerability from 2017, highlighting the long tail of unpatched vulnerabilities. Defenders should prioritize identifying and patching instances of this specific component.

## Attack Chain

1.  **Discovery**: An unauthenticated attacker identifies a Joomla! instance running the vulnerable Calendar Planner 1.0.1 component.
2.  **Vulnerability Identification**: The attacker identifies the publicly accessible 'events' view within the component and its reliance on the `category_id` GET parameter.
3.  **Payload Crafting**: The attacker crafts a malicious SQL injection payload, such as a `UNION SELECT` statement, designed to extract database schema or data.
4.  **Request Generation**: The crafted payload is embedded within the `category_id` parameter of a GET request targeting the vulnerable endpoint (e.g., `/index.php?option=com_calendarplanner&view=events&category_id=<SQL_PAYLOAD>`).
5.  **Execution**: The vulnerable Calendar Planner component processes the request, and due to improper input sanitization, executes the attacker's SQL commands on the backend database.
6.  **Information Disclosure**: The results of the malicious SQL query, containing sensitive database information, are returned in the HTTP response body to the attacker.
7.  **Data Exfiltration**: The attacker systematically iterates through database tables and columns, exfiltrating sensitive data such as user credentials, personal identifiable information (PII), or application configuration.
8.  **Impact**: The exfiltrated data can be used for further attacks, identity theft, or sale on dark web markets, leading to significant financial and reputational damage.

## Impact

A successful exploitation of CVE-2017-20267 can lead to the full compromise of the database underpinning the Joomla! installation. Attackers can exfiltrate sensitive data, including user credentials, personal information, and potentially business-critical data. This could result in severe data breaches, regulatory fines, reputational damage, and further system compromise if exfiltrated credentials are reused on other systems. The unauthenticated nature of this vulnerability means that any internet-facing instance of the vulnerable component is at risk, making the potential number of victims high if left unpatched.

## Recommendation

*   Immediately patch or uninstall Joomla! Component Calendar Planner 1.0.1 (or earlier versions) and upgrade to a secure version to remediate CVE-2017-20267.
*   Deploy the provided Sigma rule "Detects CVE-2017-20267 Exploitation — SQLi in Calendar Planner" to your SIEM for detection of exploitation attempts.
*   Ensure web application firewalls (WAFs) are configured to detect and block common SQL injection patterns, complementing the detection rule.
*   Enable comprehensive web server logging (category `webserver`) to ensure visibility into HTTP requests, including full URI-stem and URI-query fields, which are crucial for the detection rule.
