---
title: SSCMS v7.4.0 SQL Injection Vulnerability in stl:sqlContent Tag
slug: 2026-04-sscms-sqli
description: SSCMS v7.4.0 is vulnerable to SQL injection via the stl:sqlContent tag's queryString attribute, allowing attackers to execute arbitrary SQL statements through crafted payloads submitted to the /api/stl/actions/dynamic endpoint.
date: "2026-04-30T21:16:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sqli
  - cve-2026-7435
  - web-application
vendors:
  - siteserver
products:
  - SSCMS 7.4.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7435
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7435
  - https://github.com/siteserver/cms
  - https://github.com/siteserver/cms/issues/3891
  - https://www.vulncheck.com/advisories/sscms-sql-injection-via-stl-sqlcontent-querystring
rules:
  - title: Detect Suspicious SSCMS stl:sqlContent Requests
    description: Detects suspicious HTTP requests to the SSCMS /api/stl/actions/dynamic endpoint potentially exploiting the SQL injection vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SSCMS stl:sqlContent with UNION SELECT
    description: Detects potential SQL injection attempts using UNION SELECT in SSCMS stl:sqlContent requests.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SSCMS v7.4.0 is susceptible to a SQL injection vulnerability (CVE-2026-7435) within the `stl:sqlContent` tag. The vulnerability arises because the `queryString` attribute is passed directly to database execution without adequate sanitization or parameterization. This flaw enables attackers to inject malicious SQL code by crafting encrypted payloads and submitting them to the `/api/stl/actions/dynamic` endpoint. Successful exploitation can lead to unauthorized access to the database, disclosure of sensitive information, authentication bypass, modification of data, or even complete compromise of the database. This vulnerability poses a significant risk to organizations using the affected SSCMS version, potentially leading to severe data breaches and system disruption.

## Attack Chain

1.  The attacker identifies an SSCMS v7.4.0 instance.
2.  The attacker crafts a malicious SQL injection payload, specifically targeting the `queryString` attribute within the `stl:sqlContent` tag.
3.  The attacker encrypts the crafted SQL injection payload.
4.  The attacker sends the encrypted payload to the `/api/stl/actions/dynamic` endpoint using an HTTP POST request.
5.  The SSCMS application receives the request and processes the `stl:sqlContent` tag without proper sanitization.
6.  The application executes the attacker-controlled SQL query against the database.
7.  The attacker gains unauthorized access to the database, potentially extracting sensitive data or modifying existing records.
8.  The attacker may escalate privileges or move laterally within the compromised system, depending on the level of access gained.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to severe consequences. An attacker could gain complete control over the SSCMS database, potentially exposing sensitive user data, confidential business information, or proprietary intellectual property. Data breaches resulting from this vulnerability could lead to significant financial losses, reputational damage, and legal liabilities. The lack of specifics about victim count or sectors targeted makes quantification difficult, but the potential impact is high for any organization using the affected software.

## Recommendation

*   Apply any available patches or updates for SSCMS v7.4.0 to address the SQL injection vulnerability described in CVE-2026-7435.
*   Implement input validation and sanitization measures to prevent SQL injection attacks, specifically focusing on the `queryString` attribute of the `stl:sqlContent` tag.
*   Deploy the Sigma rule `Detect Suspicious SSCMS stl:sqlContent Requests` to identify potential exploitation attempts targeting the `/api/stl/actions/dynamic` endpoint.
