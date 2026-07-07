---
title: Mautic API SQL Injection Vulnerability (CVE-2026-4776)
slug: 2026-07-mautic-sql-injection-api
description: An SQL injection vulnerability, tracked as CVE-2026-4776, exists in Mautic's API contact filtering mechanism due to insufficient recursive sanitization of nested query parameters, allowing an authenticated API user to bypass input filtering, inject arbitrary SQL commands, and retrieve sensitive database contents such as user credentials, system configurations, and personal identifiable information (PII), bypassing standard data access permissions.
date: "2026-07-03T11:36:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve
  - mautic
  - ghsa
vendors:
  - Mautic
products:
  - Mautic (>= 2.6.0, <= 4.4.13)
  - Mautic (>= 5.0.0, < 5.2.11)
  - Mautic (>= 6.0.0, < 6.0.9)
  - Mautic (>= 7.0.0, < 7.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: An authenticated API user can bypass input filtering and inject arbitrary SQL commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1213
    technique_name: Exploitation for Client Execution
    evidence: An SQL injection vulnerability exists in Mautic's API contact filtering mechanism... inject arbitrary SQL commands.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1580
    technique_name: Exploitation of Remote Services
    evidence: This allows unauthorized retrieval of sensitive database contents—including user credentials, system configurations, and personal identifiable information (PII) of contacts.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1580
    technique_name: Exploitation of Remote Services
    evidence: unauthorized retrieval of sensitive database contents—including user credentials
    confidence_band: high
cves:
  - id: CVE-2026-4776
    cvss: 7.1
    epss: 0.00224
references:
  - https://github.com/advisories/GHSA-fcmw-wx57-9p75
rules:
  - title: Detects CVE-2026-4776 Exploitation — Mautic API SQL Injection
    description: Detects attempts to exploit CVE-2026-4776, an authenticated SQL injection vulnerability in Mautic's API contact filtering mechanism, by identifying suspicious SQL payloads in web server request query parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1213
      - T1580
    data_sources:
      - webserver
rules_count: 1
---

A critical SQL injection vulnerability (CVE-2026-4776) has been identified in Mautic, an open-source marketing automation platform. This flaw specifically impacts the API contact filtering mechanism, stemming from inadequate recursive sanitization of nested query parameters. Attackers can exploit this by crafting malicious API requests containing SQL injection payloads, which bypass Mautic's input filtering. The vulnerability allows an authenticated user with API access to execute arbitrary SQL commands against the underlying database. This could lead to unauthorized retrieval of sensitive information, including user credentials, system configurations, and personally identifiable information (PII) of contacts, thereby compromising data confidentiality and integrity. The issue affects Mautic versions from 2.6.0 up to 4.4.13, and specific ranges within 5.x, 6.x, and 7.x, with patches released in versions 7.1.2, 6.0.9, 5.2.11, and 4.4.20.

## Attack Chain

1.  **Initial Access**: An attacker obtains valid credentials for a Mautic user account with API access permissions.
2.  **API Request Crafting**: The attacker crafts a specially malformed API request targeting Mautic's contact filtering endpoint (e.g., `/api/contacts`).
3.  **SQL Payload Injection**: The malicious request includes an SQL injection payload embedded within nested query parameters, designed to bypass Mautic's existing input sanitization for CVE-2026-4776.
4.  **Backend Processing**: Mautic's API processes the request, and due to the vulnerability, fails to properly sanitize the injected SQL commands.
5.  **SQL Execution**: The unsanitized SQL payload is executed directly against the backend database server (e.g., MySQL, PostgreSQL).
6.  **Data Exfiltration**: The malicious SQL query extracts sensitive information from the database, such as administrator credentials, system configurations, or PII.
7.  **Data Retrieval**: The extracted sensitive data is returned as part of the legitimate API response, allowing the authenticated attacker to retrieve it.

## Impact

Successful exploitation of CVE-2026-4776 grants an authenticated user with API access the ability to execute arbitrary SQL queries against Mautic's backend database. This has severe implications, as it enables unauthorized access and retrieval of sensitive database contents. This includes, but is not limited to, user credentials (potentially including hashed passwords), critical system configurations, and all personal identifiable information (PII) stored for marketing contacts. This bypasses standard data access permissions, potentially exposing millions of records in larger Mautic deployments and leading to significant data breaches, reputational damage, and regulatory penalties.

## Recommendation

*   **Patch CVE-2026-4776 immediately**: Upgrade Mautic to one of the patched versions: 7.1.2, 6.0.9, 5.2.11, or 4.4.20.
*   **Implement WAF rules**: Deploy a Web Application Firewall (WAF) and configure rules to detect and block common SQL injection patterns, especially those targeting query parameters of Mautic API endpoints as outlined in the Sigma rule.
*   **Restrict API access**: If immediate patching is not possible, temporarily disable Mautic API access or restrict API permissions to only highly trusted accounts as a mitigation described in the brief.
*   **Monitor webserver logs**: Deploy the provided Sigma rule to your SIEM to detect attempts to exploit CVE-2026-4776 by monitoring your webserver logs for suspicious API requests.
