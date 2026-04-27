---
title: WordPress adivaha Travel Plugin SQL Injection Vulnerability (CVE-2023-54359)
slug: 2026-04-adivaha-sql-injection
description: The WordPress adivaha Travel Plugin version 2.3 is vulnerable to time-based blind SQL injection via the 'pid' GET parameter, allowing unauthenticated attackers to inject SQL code through the /mobile-app/v3/ endpoint for potential data extraction or denial of service.
date: "2026-04-09T21:16:05Z"
severities:
  - high
exploited: true
tags:
  - wordpress
  - sql-injection
  - cve-2023-54359
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2023-54359
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54359
  - https://www.exploit-db.com/exploits/51655
  - https://www.vulncheck.com/advisories/wordpress-adivaha-travel-plugin-sql-injection-via-pid
ioc_counts:
  url: 2
rules:
  - title: Detect Suspicious adivaha Travel Plugin SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the adivaha Travel Plugin by monitoring the 'pid' parameter in requests to the /mobile-app/v3/ endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect adivaha Travel Plugin Exploitation via Exploit-DB URL
    description: Detects access to the Exploit-DB page referencing the adivaha Travel Plugin SQL injection vulnerability, potentially indicating reconnaissance or active exploitation.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - proxy
      - windows
rules_count: 2
---

The adivaha Travel plugin 2.3 for WordPress is susceptible to a time-based blind SQL injection vulnerability (CVE-2023-54359). This flaw allows unauthenticated attackers to inject malicious SQL code through the 'pid' GET parameter in requests to the `/mobile-app/v3/` endpoint. By crafting specific 'pid' values with XOR-based payloads, attackers can manipulate database queries. This vulnerability can be exploited to extract sensitive database information or to cause a denial-of-service condition…
