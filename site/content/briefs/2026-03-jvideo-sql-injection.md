---
title: ASP.NET jVideo Kit 1.0 SQL Injection Vulnerability
slug: 2026-03-jvideo-sql-injection
description: ASP.NET jVideo Kit 1.0 is vulnerable to SQL injection via the 'query' parameter in the search functionality, allowing unauthenticated attackers to inject malicious SQL payloads to extract sensitive database information.
date: "2026-03-26T12:16:05Z"
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - asp.net
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25205
  - https://www.exploit-db.com/exploits/44739
  - https://www.mediasoftpro.com/video-sharing-script/mvc/
  - https://www.vulncheck.com/advisories/asp-net-jvideo-kit-sql-injection-via-query-parameter
rules:
  - title: Detect SQL Injection Attempts in jVideo Kit Search
    description: Detects potential SQL injection attempts targeting the /search endpoint in ASP.NET jVideo Kit 1.0 by looking for common SQL injection keywords in the query parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
  - title: Detect SQL Injection Error Responses
    description: Detects potential SQL injection attempts by monitoring web server logs for specific error status codes and messages associated with SQL errors after a request to /search
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
---

ASP.NET jVideo Kit 1.0 is susceptible to an SQL injection vulnerability (CVE-2018-25205) affecting its search functionality. This vulnerability enables unauthenticated attackers to inject arbitrary SQL commands by manipulating the 'query' parameter. The attack can be carried out via both GET and POST requests directed towards the `/search` endpoint. Successful exploitation allows attackers to perform boolean-based blind or error-based SQL injection techniques, potentially leading to the…
