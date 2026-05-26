---
title: Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform SQL Injection Vulnerability (CVE-2026-9523)
slug: 2026-05-acrel-sql-injection
description: A SQL injection vulnerability (CVE-2026-9523) exists in Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform 3000WEBV2, where manipulating the 'sort' argument in the '/SubstationWEBV2/app/..;/calc/getCalcmeterDetailDayListTree' file leads to remote code execution, and is publicly known and actively exploited.
date: "2026-05-26T14:27:03Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sql-injection
  - cve-2026-9523
  - web-application
vendors:
  - Acrel Electrical
products:
  - EEMS Enterprise Power Operation and Maintenance Cloud Platform 3000WEBV2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-9523
    cvss: 7.3
    epss: 0.00028
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9523
rules:
  - title: Detect CVE-2026-9523 Exploitation Attempt via Malicious sort Parameter
    description: Detects CVE-2026-9523 exploitation attempt via a malicious sort parameter containing SQL injection payloads
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Acrel Electrical's EEMS Enterprise Power Operation and Maintenance Cloud Platform 3000WEBV2 is vulnerable to SQL injection. The vulnerability, identified as CVE-2026-9523, allows an attacker to execute arbitrary SQL commands by manipulating the `sort` argument in a specific file path. This flaw was found in the `/SubstationWEBV2/app/..;/calc/getCalcmeterDetailDayListTree` endpoint. The vulnerability is remotely exploitable and has a CVSS v3.1 base score of 7.3. This issue is considered high risk because successful exploitation can lead to unauthorized data access, modification, or even complete system compromise. Despite attempts to contact the vendor, no response has been received, leaving users vulnerable to potential attacks. Public availability of the exploit code increases the risk of widespread exploitation.

## Attack Chain

1. The attacker identifies a vulnerable instance of Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform 3000WEBV2.
2. The attacker crafts a malicious HTTP GET or POST request targeting the `/SubstationWEBV2/app/..;/calc/getCalcmeterDetailDayListTree` endpoint.
3. The crafted request includes a manipulated `sort` parameter containing a SQL injection payload.
4. The application fails to properly sanitize the `sort` parameter, passing the malicious SQL code to the database.
5. The database executes the attacker-supplied SQL code.
6. The attacker retrieves sensitive information from the database, such as user credentials or system configurations.
7. The attacker may escalate privileges by injecting SQL code to create new administrative accounts.
8. The attacker gains full control of the application and underlying system, potentially leading to data exfiltration or service disruption.

## Impact

Successful exploitation of this vulnerability can lead to a full compromise of the affected Acrel Electrical EEMS Enterprise Power Operation and Maintenance Cloud Platform 3000WEBV2. This can result in unauthorized access to sensitive data, including customer information, operational data, and system configurations. Attackers can modify or delete data, disrupt services, or use the compromised system as a launchpad for further attacks. The lack of vendor response exacerbates the risk, as users are left without official patches or mitigation guidance. The public availability of exploit code increases the likelihood of widespread attacks.

## Recommendation

*   Inspect web server logs for requests targeting `/SubstationWEBV2/app/..;/calc/getCalcmeterDetailDayListTree` with suspicious characters or SQL keywords in the `sort` parameter to detect potential exploitation attempts.
*   Deploy the Sigma rule "Detect CVE-2026-9523 Exploitation Attempt via Malicious sort Parameter" to identify suspicious HTTP requests.
*   Implement input validation and sanitization on the `sort` parameter to prevent SQL injection attacks.
