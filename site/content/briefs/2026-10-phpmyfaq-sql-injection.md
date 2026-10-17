---
title: SQL Injection in phpMyFAQ via PdoMysql::escape()
slug: 2026-10-phpmyfaq-sql-injection
description: An unauthenticated SQL injection vulnerability in phpMyFAQ versions prior to 4.1.9 allows attackers to exfiltrate data and manipulate database records by injecting Unicode characters into the api/autocomplete endpoint.
date: "2026-10-13T00:31:30Z"
lastmod: "2026-10-17T20:53:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:phpmyfaq:phpmyfaq:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve
  - authentication-bypass
  - sso
  - cve-2026-111882
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ (< 4.1.9)
  - phpMyFAQ (3.2.0-alpha to < 4.1.9)
  - phpMyFAQ (4.2.0-alpha to < 4.2.0-beta)
  - phpMyFAQ (< 4.1.9, 4.2.0-alpha before 4.2.0-beta)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can send a Unicode right single quotation mark in the search parameter of api/autocomplete to read credentials and configuration secrets.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can stage a victim username, submit a forged fmt=none attestation to register a passkey, then log in bypassing passwords and TOTP for account takeover.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers can stage a victim username, submit a forged fmt=none attestation to register a passkey, then log in bypassing passwords and TOTP for account takeover.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An attacker with a hijacked session can set the e-mail to their own mailbox and use the password-reset flow to take over non-2FA accounts.
    confidence_band: high
cves:
  - id: CVE-2026-109573
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109573
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111911
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111882
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111884
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade phpMyFAQ to version 4.1.9 or later
      owner: IT Operations
      due: 24h
      evidence: Source states phpMyFAQ before 4.1.9 contains an SQL injection vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 4.1.9
      owner: IT Operations
      addresses: CVE-2026-109573
      evidence: Source states phpMyFAQ before 4.1.9 contains the vulnerability
updates:
  - at: "2026-10-17T20:53:08Z"
    level: L2
    summary: added coverage for phpMyFAQ (< 4.1.9)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111911
  - at: "2026-10-17T20:53:26Z"
    level: L2
    summary: added coverage for phpMyFAQ (3.2.0-alpha to < 4.1.9) +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111882
  - at: "2026-10-17T20:53:33Z"
    level: L2
    summary: added coverage for phpMyFAQ (< 4.1.9, 4.2.0-alpha before 4.2.0-beta)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111884
---

phpMyFAQ versions prior to 4.1.9 are susceptible to a critical SQL injection vulnerability within the `PdoMysql::escape()` function. The flaw occurs because the function attempts to sanitize inputs by escaping single quotes with backslashes; however, this mechanism fails when the backend MySQL or MariaDB database is configured with the `NO_BACKSLASH_ESCAPES` SQL mode. In this environment, the backslashes are treated as literal characters rather than escape sequences.

Unauthenticated attackers can exploit this by sending a specially crafted Unicode right single quotation mark in the `search` parameter of the `api/autocomplete` API endpoint. The application normalizes this character into an ASCII single quote, successfully bypassing the intended sanitization. If successfully exploited, this vulnerability provides an attacker with the ability to perform unauthorized credential extraction, leak configuration secrets, modify existing records, or drop entire database tables. Organizations running phpMyFAQ should upgrade to version 4.1.9 or later immediately to mitigate this risk.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to achieve unauthorized access to the application's backend database. This may result in full data exfiltration, including administrative credentials and system configuration, as well as destructive actions such as record modification or complete table deletion.

## Recommendation

* Upgrade phpMyFAQ to version 4.1.9 or later immediately to resolve the vulnerable `PdoMysql::escape()` implementation.
* Monitor web server logs for HTTP requests directed at `api/autocomplete` containing Unicode characters or suspicious SQL syntax within the `search` query parameter.
* Review database configurations to determine if `NO_BACKSLASH_ESCAPES` is enabled, as this setting amplifies the impact of the vulnerability.
