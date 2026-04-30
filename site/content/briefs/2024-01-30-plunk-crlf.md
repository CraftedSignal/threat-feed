---
title: Plunk Email Platform CRLF Header Injection Vulnerability
slug: 2024-01-30-plunk-crlf
description: A CRLF header injection vulnerability in Plunk versions prior to 0.8.0 allows authenticated API users to inject arbitrary email headers, enabling silent email forwarding, reply redirection, or sender spoofing.
date: "2026-04-06T17:17:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - crlf
  - header-injection
  - plunk
  - cve-2026-34975
  - cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1587
    technique_name: Develop Capabilities
cves:
  - id: CVE-2026-34975
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34975
rules:
  - title: Detect Suspicious CRLF Characters in URI Query
    description: Detects suspicious carriage return and line feed characters in URI queries, potentially indicating CRLF injection attempts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1587.002
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious CRLF Characters in HTTP Request Body
    description: Detects suspicious carriage return and line feed characters in HTTP request body, potentially indicating CRLF injection attempts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1587.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Plunk, an open-source email platform built on top of AWS SES, is vulnerable to CRLF header injection. Prior to version 0.8.0, the application failed to properly sanitize user-supplied values for fields like `from.name`, `subject`, custom header keys/values, and attachment filenames. This vulnerability, identified as CVE-2026-34975, allows an authenticated API user to inject arbitrary email headers by including carriage return (`\r`) and line feed (`\n`) characters in these fields. Successful exploitation could lead to silent email forwarding to unauthorized recipients, redirection of replies to attacker-controlled addresses, and spoofing of the sender's identity. The vulnerability was addressed in Plunk version 0.8.0 by implementing input validation to reject any of the affected fields containing `\r` or `\n` characters. Defenders should ensure Plunk installations are upgraded to version 0.8.0 or later.

## Attack Chain

1. An attacker gains authenticated access to the Plunk API.
2. The attacker crafts a malicious API request to send an email.
3. In the `from.name`, `subject`, custom header keys/values, or attachment filename fields, the attacker injects carriage return (`\r`) and line feed (`\n`) characters followed by arbitrary email headers. For example: `Subject: legitimate subject\r\nBcc: attacker@example.com`.
4. The Plunk application, prior to version 0.8.0, processes the request without proper sanitization. The injected CRLF sequences are interpreted as header delimiters, and the attacker-supplied headers are added to the email.
5. The Plunk application constructs a raw MIME message including the injected headers.
6. Plunk sends the email via AWS SES.
7. The recipient receives the email, which now includes the attacker-injected headers (e.g., `Bcc`, `Reply-To`).
8. The attacker achieves their objective, such as silently receiving a copy of the email (Bcc), redirecting replies to an attacker-controlled address (Reply-To), or impersonating another sender (From).

## Impact

Successful exploitation of the CRLF injection vulnerability (CVE-2026-34975) in Plunk can lead to significant confidentiality and integrity breaches. Attackers can silently intercept sensitive email communications by adding themselves as Bcc recipients. They can also redirect replies to attacker-controlled addresses, potentially gaining access to further information. Furthermore, attackers can spoof the sender's identity, enabling them to conduct phishing attacks or distribute malicious content under the guise of a trusted source. The number of potential victims is proportional to the number of Plunk users and the sensitivity of the information they handle. The risk is particularly high for organizations using Plunk to manage critical communications or sensitive data.

## Recommendation

*   Upgrade Plunk to version 0.8.0 or later to remediate CVE-2026-34975, which introduces input validation to prevent CRLF injection.
*   Monitor Plunk application logs for suspicious API requests containing carriage return (`\r`) or line feed (`\n`) characters in email fields. Implement a rule to detect these characters in `cs-uri-query` within the webserver logs.
*   Implement input validation on any custom email sending functionality to prevent CRLF injection vulnerabilities.
