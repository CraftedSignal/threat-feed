---
title: WordPress Court Reservation Plugin SQL Injection Vulnerability (CVE-2026-1250)
slug: 2026-05-wordpress-court-reservation-sqli
description: The Court Reservation – Manage Your Court Bookings Online plugin for WordPress versions 1.10.11 and earlier are vulnerable to SQL injection via the 'id' parameter, enabling unauthenticated attackers to extract sensitive database information.
date: "2026-05-12T23:17:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - wordpress
  - plugin
  - CVE-2026-1250
  - web-application
vendors:
  - WordPress
products:
  - The Court Reservation – Manage Your Court Bookings Online plugin for WordPress <= 1.10.11
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-1250
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1250
rules:
  - title: Detect WordPress Court Reservation Plugin SQL Injection (CVE-2026-1250)
    description: Detects CVE-2026-1250 exploitation — SQL injection attempts in the 'id' parameter of the Court Reservation plugin for WordPress.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect WordPress Court Reservation Plugin SQL Injection - Error Based
    description: Detects CVE-2026-1250 exploitation — Error-based SQL injection attempts in the 'id' parameter of the Court Reservation plugin for WordPress by looking for common SQL error messages in the response.
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

CVE-2026-1250 identifies a SQL injection vulnerability affecting the Court Reservation – Manage Your Court Bookings Online plugin for WordPress, impacting all versions up to and including 1.10.11. The vulnerability stems from insufficient escaping of the user-supplied 'id' parameter within SQL queries, coupled with a lack of adequate preparation of these queries. This flaw allows unauthenticated attackers to inject arbitrary SQL commands into existing queries, potentially leading to the extraction of sensitive data from the WordPress database. This vulnerability poses a significant risk to website owners using the affected plugin, as attackers could gain access to user credentials, financial information, or other confidential data stored within the database.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress website using a vulnerable version (<= 1.10.11) of the Court Reservation plugin.
2.  The attacker crafts a malicious HTTP request targeting an endpoint that utilizes the 'id' parameter (e.g., a page or API endpoint that displays court reservation details).
3.  The attacker injects SQL code into the 'id' parameter within the HTTP request. For example, `id=1' OR '1'='1`.
4.  The WordPress application processes the request, passing the unsanitized 'id' parameter to the vulnerable SQL query.
5.  The injected SQL code is executed within the database context, potentially modifying the query's original intent.
6.  The attacker uses SQL injection techniques like `UNION SELECT` to extract sensitive data from other database tables, such as user credentials or configuration information.
7.  The database returns the results of the modified query, which now includes the attacker-requested data.
8.  The attacker retrieves the extracted sensitive information from the HTTP response.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-1250) allows unauthenticated attackers to access sensitive information stored in the WordPress database. This can include user credentials (usernames, passwords, email addresses), personal information, and potentially financial data if stored in the database. The impact can range from account compromise and identity theft to data breaches and financial loss. Given the widespread use of WordPress and its plugins, a successful exploit could affect a significant number of websites and their users.

## Recommendation

*   Upgrade the Court Reservation – Manage Your Court Bookings Online plugin to the latest version, which contains a patch for CVE-2026-1250.
*   Deploy the Sigma rule "Detect WordPress Court Reservation Plugin SQL Injection (CVE-2026-1250)" to detect exploitation attempts targeting the vulnerable 'id' parameter.
*   Implement a web application firewall (WAF) rule to filter out requests containing potentially malicious SQL injection payloads in the 'id' parameter.
*   Review WordPress database logs for suspicious queries containing SQL injection syntax.
