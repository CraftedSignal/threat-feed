---
title: MooSocial Store Plugin 2.6 Blind SQL Injection Vulnerability (CVE-2018-25371)
slug: 2026-05-moosocial-sqli
description: MooSocial Store Plugin 2.6 contains a blind SQL injection vulnerability, identified as CVE-2018-25371, allowing unauthenticated attackers to manipulate database queries via the 'product' parameter, potentially leading to sensitive data extraction.
date: "2026-05-26T14:14:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - web-application
  - cve-2018-25371
vendors:
  - mooSocial
products:
  - Store Plugin 2.6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25371
    cvss: 8.2
    epss: 0.00068
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25371
  - http://addons.moosocial.com/stores
  - https://moosocial.com/product/store-plugins/
  - https://www.exploit-db.com/exploits/45330
  - https://www.vulncheck.com/advisories/moosocial-store-plugin-sql-injection-via-product-parameter
rules:
  - title: Detects CVE-2018-25371 Exploitation — MooSocial Store Plugin SQL Injection Attempt
    description: Detects CVE-2018-25371 exploitation attempts in MooSocial Store Plugin 2.6 by identifying SQL injection payloads in the 'product' parameter of HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detects CVE-2018-25371 Exploitation — MooSocial Store Plugin SQL Injection Attempt (Time-Based)
    description: Detects CVE-2018-25371 exploitation attempts in MooSocial Store Plugin 2.6 by identifying time-based SQL injection payloads in the 'product' parameter of HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
---

The MooSocial Store Plugin version 2.6 is susceptible to a blind SQL injection vulnerability (CVE-2018-25371). This flaw enables unauthenticated attackers to inject malicious SQL code through the 'product' parameter within the URL rewrite functionality. The exploitation of this vulnerability allows attackers to manipulate database queries using techniques such as boolean-based blind SQL injection, time-based blind SQL injection, and stacked queries. Successful exploitation can result in the unauthorized extraction of sensitive information stored within the database. Defenders should prioritize identifying and mitigating this vulnerability to prevent potential data breaches.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP request to a MooSocial application running the vulnerable Store Plugin 2.6.
2. The request targets a URL that uses the product parameter in URL rewrite functionality.
3. The attacker injects malicious SQL code into the product parameter of the URL.
4. The application processes the crafted URL, and the injected SQL code is executed against the database.
5. Due to the blind SQL injection nature, the attacker infers the results of the query by observing the application's response or timing.
6. Using techniques like boolean-based or time-based blind SQL injection, the attacker iteratively extracts sensitive data.
7. Extracted data may include user credentials, database schema information, or other confidential data.
8. The attacker exfiltrates the sensitive information, potentially leading to further compromise of the application and its data.

## Impact

Successful exploitation of this vulnerability can lead to unauthorized access to sensitive data stored in the MooSocial application's database. This can result in data breaches, compromised user accounts, and potential reputational damage for the affected organization. The impact is heightened by the unauthenticated nature of the vulnerability, allowing any attacker to potentially exploit it.

## Recommendation

- Deploy the Sigma rule to detect potential exploitation attempts against the vulnerable application using web server logs, monitoring for suspicious characters in the product parameter (cs-uri-query).
- Examine web server access logs for requests containing SQL injection payloads in the `product` parameter of URLs.
- Apply input validation and sanitization to the `product` parameter to prevent SQL injection attacks.
- Upgrade to a patched version of the MooSocial Store Plugin that addresses the CVE-2018-25371 vulnerability.
- Review and restrict database user privileges to minimize the impact of successful SQL injection attacks.
