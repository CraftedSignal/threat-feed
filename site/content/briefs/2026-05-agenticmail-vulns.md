---
title: AgenticMail API and Core Packages Vulnerabilities
slug: 2026-05-agenticmail-vulns
description: Multiple vulnerabilities, including SQL injection and SMTP header injection, have been discovered in AgenticMail API and Core packages, addressed in versions greater than 0.9.31 and 0.9.9 respectively, posing a risk of unauthorized access and control.
date: "2026-05-29T19:24:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - sqlinjection
  - smtpheaderinjection
products:
  - '@agenticmail/api (<= 0.9.31)'
  - '@agenticmail/core (<= 0.9.9)'
references:
  - https://github.com/advisories/GHSA-wjjv-3mj2-39hf
  - CVE-2026-47255
rules:
  - title: Detect CVE-2026-47255 Attempt - Suspicious SQL Query Parameters
    description: Detects potential CVE-2026-47255 exploitation attempts by identifying suspicious SQL-like syntax in HTTP request parameters targeting AgenticMail applications.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-47255 Attempt - Suspicious Characters in SMTP Headers
    description: Detects potential CVE-2026-47255 exploitation attempts via suspicious control characters in SMTP headers, which could indicate an SMTP header injection attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Multiple vulnerabilities have been identified in AgenticMail API and Core packages. These include insufficient validation in inactive-agent hour filtering, storage SQL identifiers, and SMTP envelope/header control-character validation. Additionally, the advisory highlights missing metadata-backed ownership checks for raw storage SQL, direct storage metadata access through raw SQL, and insecure handling of outbound worker secrets. The issues are addressed in versions later than 0.9.31 for @agenticmail/api and later than 0.9.9 for @agenticmail/core. The validated fixes were rebased on 2026-05-18. This matters for defenders as exploitation of these vulnerabilities could lead to unauthorized data access, code execution, and control over email sending capabilities.

## Attack Chain

1.  Attacker identifies a vulnerable AgenticMail instance running a version of @agenticmail/api <= 0.9.31 or @agenticmail/core <= 0.9.9.
2.  If exploiting the SQL injection, the attacker crafts a malicious SQL query leveraging insufficient validation of storage SQL identifiers (CVE-2026-47255).
3.  The crafted SQL query is injected into the application through a vulnerable API endpoint, bypassing input sanitization.
4.  The injected SQL commands execute against the AgenticMail database, potentially allowing the attacker to read, modify, or delete sensitive data.
5.  If exploiting SMTP header injection, attacker manipulates email headers via insufficiently validated SMTP envelope/header control-characters (CVE-2026-47255).
6.  The manipulated email headers can be used to spoof sender addresses, inject malicious content, or redirect email traffic.
7.  The attacker uses the compromised email functionality to send phishing emails, distribute malware, or conduct other malicious activities.

## Impact

Successful exploitation of these vulnerabilities could allow attackers to gain unauthorized access to sensitive data stored within AgenticMail, including user credentials, email content, and configuration settings. Attackers could also leverage the vulnerabilities to manipulate email sending capabilities, enabling them to conduct phishing campaigns, distribute malware, or disrupt email communications. The lack of TLS certificate verification could further expose sensitive data during email transmission if the explicit opt-out for local development is misused in production.

## Recommendation

*   Upgrade the `@agenticmail/api` package to a version greater than 0.9.31 to remediate the vulnerabilities related to API handling, input validation, and SQL injection (CVE-2026-47255).
*   Upgrade the `@agenticmail/core` package to a version greater than 0.9.9 to address vulnerabilities related to core functionality, SQL validation, and SMTP header injection (CVE-2026-47255).
*   Implement robust input validation and sanitization measures to prevent SQL injection and SMTP header injection attacks as an additional layer of defense.
*   Enable TLS certificate verification for MailSender to ensure secure email transmission, and avoid using the explicit opt-out except for local development purposes.
