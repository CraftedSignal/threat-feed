---
title: WordPress adivaha Travel Plugin SQL Injection Vulnerability (CVE-2023-54359)
slug: 2026-04-adivaha-sql-injection
description: The WordPress adivaha Travel Plugin version 2.3 is vulnerable to time-based blind SQL injection via the 'pid' GET parameter, allowing unauthenticated attackers to inject SQL code through the /mobile-app/v3/ endpoint for potential data extraction or denial of service.
date: "2026-04-09T21:16:05Z"
severities:
  - high
exploited: true
type: threat
types:
  - threat
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
iocs:
  - type: url
    value: https://www.exploit-db.com/exploits/51655
  - type: url
    value: https://www.vulncheck.com/advisories/wordpress-adivaha-travel-plugin-sql-injection-via-pid
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

The adivaha Travel plugin 2.3 for WordPress is susceptible to a time-based blind SQL injection vulnerability (CVE-2023-54359). This flaw allows unauthenticated attackers to inject malicious SQL code through the 'pid' GET parameter in requests to the `/mobile-app/v3/` endpoint. By crafting specific 'pid' values with XOR-based payloads, attackers can manipulate database queries. This vulnerability can be exploited to extract sensitive database information or to cause a denial-of-service condition on the affected WordPress site. Publicly available exploits exist, increasing the risk of widespread exploitation.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress site using the vulnerable adivaha Travel Plugin version 2.3.
2. The attacker crafts a malicious HTTP GET request targeting the `/mobile-app/v3/` endpoint.
3. The attacker injects SQL code into the `pid` GET parameter, utilizing XOR-based payloads to bypass input validation or sanitization.
4. The server processes the malicious SQL query against the WordPress database.
5. Due to the time-based blind SQL injection, the attacker infers information about the database by observing the response time of the server.
6. Through repeated requests, the attacker extracts sensitive data from the database, such as user credentials, API keys, or other confidential information.
7. Alternatively, the attacker injects SQL code to cause a denial-of-service condition, such as by creating a very long delay.
8. The attacker uses the exfiltrated data for malicious purposes or further compromise of the WordPress site.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to the extraction of sensitive information from the WordPress database, potentially compromising user accounts, customer data, and other confidential information. Attackers could gain complete control over the affected website, leading to defacement, malware distribution, or further attacks on other systems. A successful denial-of-service attack could also disrupt the availability of the website, impacting business operations and user experience.

## Recommendation

*   Apply any available patches or updates for the adivaha Travel Plugin to remediate CVE-2023-54359.
*   Deploy the Sigma rule `Detect Suspicious adivaha Travel Plugin SQL Injection Attempt` to your SIEM to identify potential exploitation attempts targeting the `/mobile-app/v3/` endpoint.
*   Inspect web server logs for requests to `/mobile-app/v3/` containing suspicious characters or SQL syntax in the `pid` parameter to identify exploitation attempts (reference: vulnerable endpoint `/mobile-app/v3/`).
*   Monitor network traffic for connections to the URLs listed in the IOCs (reference: `https://www.exploit-db.com/exploits/51655` and `https://www.vulncheck.com/advisories/wordpress-adivaha-travel-plugin-sql-injection-via-pid`).
