---
title: Metasoft MetaCRM SQL Injection Vulnerability (CVE-2026-6629)
slug: 2026-04-metasoft-crm-sql-injection
description: A SQL injection vulnerability (CVE-2026-6629) exists in Metasoft MetaCRM up to version 6.4.0, allowing remote attackers to execute arbitrary SQL commands via manipulation of the sql argument in the Statement.executeUpdate function of the sql.jsp file.
date: "2026-04-20T11:16:18Z"
severities:
  - high
tags:
  - cve-2026-6629
  - sql-injection
  - web-application
  - metasoft
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6629
  - https://my.feishu.cn/docx/JttndUaPLoR88HxI1alcz1uencf?from=from_copylink
  - https://vuldb.com/submit/792615
  - https://vuldb.com/vuln/358263
  - https://vuldb.com/vuln/358263/cti
rules:
  - title: Detect Metasoft MetaCRM SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the sql.jsp file in Metasoft MetaCRM by looking for suspicious SQL syntax in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Metasoft MetaCRM SQL Error
    description: Detects SQL errors returned by the server, which could indicate a successful SQL injection.
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

A SQL injection vulnerability, identified as CVE-2026-6629, has been discovered in Metasoft 美特软件 MetaCRM versions up to 6.4.0. The vulnerability resides within the `sql.jsp` file, specifically affecting the `Statement.executeUpdate` function of the Interface component. The vulnerability allows remote attackers to inject arbitrary SQL commands by manipulating the `sql` argument. Public exploit code is available, increasing the risk of exploitation. The vendor was notified but did not…
