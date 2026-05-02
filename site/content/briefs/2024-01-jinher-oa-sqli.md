---
title: Jinher OA 1.0 SQL Injection Vulnerability (CVE-2026-7670)
slug: 2024-01-jinher-oa-sqli
description: Jinher OA 1.0 is vulnerable to remote SQL injection via the DeptIDList parameter in the /C6/JHSoft.Web.PlanSummarize/UserSel.aspx file, potentially allowing attackers to execute arbitrary SQL queries.
date: "2026-05-02T23:16:16Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - cve-2026-7670
  - web-application
vendors:
  - Jinher
products:
  - OA 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7670
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7670
rules:
  - title: Detect Jinher OA SQL Injection Attempt via DeptIDList
    description: Detects potential SQL injection attempts targeting the DeptIDList parameter in Jinher OA 1.0
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Generic SQL Injection Attempt
    description: Detects generic SQL injection attempts based on common SQL keywords in URI queries
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

A SQL injection vulnerability, identified as CVE-2026-7670, affects Jinher OA 1.0, a web-based office automation software. The vulnerability resides within the /C6/JHSoft.Web.PlanSummarize/UserSel.aspx file, specifically in how the application handles the 'DeptIDList' argument. An unauthenticated remote attacker can manipulate this argument to inject malicious SQL code into database queries. The vulnerability was reported to the vendor; however, there has been no response, and an exploit is publicly available. This lack of response and the availability of an exploit increases the risk to organizations using the affected Jinher OA 1.0.

## Attack Chain

1.  An attacker identifies a Jinher OA 1.0 instance exposed to the internet.
2.  The attacker crafts a malicious HTTP GET or POST request targeting the `/C6/JHSoft.Web.PlanSummarize/UserSel.aspx` endpoint.
3.  The request includes a modified `DeptIDList` parameter containing SQL injection payloads.
4.  The server-side application fails to properly sanitize or validate the `DeptIDList` input.
5.  The unsanitized input is passed directly into a SQL query executed against the underlying database.
6.  The injected SQL code is executed by the database server, potentially allowing the attacker to bypass authentication, extract sensitive data, or modify data.
7.  The attacker retrieves sensitive information, such as user credentials, internal configurations, or financial data, depending on the database structure and injected SQL commands.
8.  The attacker leverages compromised data to gain further access, escalate privileges, or conduct lateral movement within the organization's network.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-7670) can lead to unauthorized access to sensitive data, including user credentials, financial records, and internal communications. An attacker could potentially gain complete control over the affected Jinher OA 1.0 system and the underlying database. This could result in significant data breaches, financial losses, reputational damage, and disruption of business operations. Given the lack of vendor response, organizations using Jinher OA 1.0 are particularly vulnerable and should take immediate action to mitigate this risk.

## Recommendation

*   Inspect web server logs for requests to `/C6/JHSoft.Web.PlanSummarize/UserSel.aspx` containing suspicious characters or SQL keywords within the `DeptIDList` parameter, as covered by the Sigma rule "Detect Jinher OA SQL Injection Attempt via DeptIDList".
*   Apply input validation and sanitization to all user-supplied data, especially the `DeptIDList` parameter in `/C6/JHSoft.Web.PlanSummarize/UserSel.aspx`, to prevent SQL injection attacks.
*   Deploy the Sigma rule "Detect Generic SQL Injection Attempt" to identify broader SQL injection attempts across your web applications.
*   Given the vendor's lack of response, consider isolating the affected Jinher OA 1.0 instance from the network or replacing it with a more secure alternative.
