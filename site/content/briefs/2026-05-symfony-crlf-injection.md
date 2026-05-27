---
title: Symfony Email Header / SMTP Command Injection via CRLF Characters
slug: 2026-05-symfony-crlf-injection
description: Symfony's Mime Address component is susceptible to email header and SMTP command injection due to accepting CRLF characters within email addresses, leading to potential header manipulation or unauthorized SMTP commands in symfony/mime and symfony/symfony versions prior to 5.4.52, versions 6.0.0 to before 6.4.40, versions 7.0.0 to before 7.4.12 and versions 8.0.0 to before 8.0.12.
date: "2026-05-27T20:42:55Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - crlf-injection
  - email-injection
  - symfony
  - CVE-2026-45067
vendors:
  - Symfony
products:
  - symfony/mime
  - symfony/symfony
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-qpmx-3rfj-7rhv
  - CVE-2026-45067
rules:
  - title: Detect CVE-2026-45067 Exploitation — Email Address CRLF Injection Attempt
    description: Detects CVE-2026-45067 exploitation — Attempts to inject CRLF characters into email addresses, indicating a potential header or SMTP command injection attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-45067 Exploitation — Email Address CRLF Injection Attempt in POST body
    description: Detects CVE-2026-45067 exploitation — Attempts to inject CRLF characters into email addresses within POST request bodies, indicating a potential header or SMTP command injection attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Symfony, a popular PHP framework, is affected by a critical vulnerability in its Mime component. Specifically, the `Symfony\Component\Mime\Address` class, responsible for validating and handling email addresses, fails to properly sanitize or reject addresses containing CRLF characters (`\r\n`). This flaw allows an attacker to inject arbitrary email headers or even execute unauthorized SMTP commands by crafting a malicious email address. The vulnerability impacts applications using vulnerable versions of `symfony/mime` and `symfony/symfony`, potentially leading to spoofing, spamming, or other malicious activities. Versions affected include those prior to 5.4.52, versions 6.0.0 to before 6.4.40, versions 7.0.0 to before 7.4.12 and versions 8.0.0 to before 8.0.12. This vulnerability is identified as CVE-2026-45067 and has a severity rating of High.

## Attack Chain

1. An attacker crafts a malicious email address containing CRLF characters within the local-part (before the @ symbol), such as `"x\r\nBcc: attacker@evil"@example.com`.
2. The vulnerable Symfony application accepts this email address through a form, API, or other input vector, passing it to the `Symfony\Component\Mime\Address` constructor.
3. The `Address` constructor, instead of rejecting the address, stores it verbatim.
4. The application uses the stored email address in the "To," "From," "CC," or "BCC" fields of an email message.
5. When the email message is rendered, the injected CRLF characters create a new header, such as "Bcc: attacker@evil," effectively adding the attacker to the recipient list.
6. If the application uses `SmtpTransport`, the malicious address is also passed to the `MAIL FROM:<...>` or `RCPT TO:<...>` commands.
7. The SMTP server interprets the injected CRLF as a command separator, potentially allowing the attacker to execute arbitrary SMTP commands.
8. The attacker successfully injects headers or commands, leading to unauthorized email delivery, spoofing, or other malicious actions.

## Impact

Successful exploitation of this vulnerability allows attackers to inject arbitrary email headers, potentially leading to the distribution of spam or phishing emails that appear to originate from a trusted source. Furthermore, the ability to inject SMTP commands could allow attackers to bypass security measures and gain unauthorized access to email servers. The number of affected applications is potentially large, given the widespread use of Symfony in web development. If exploited, this vulnerability could lead to significant reputational damage, financial losses, and legal liabilities for affected organizations.

## Recommendation

*   Upgrade to Symfony `symfony/mime` and `symfony/symfony` version 5.4.52 or higher, 6.4.40 or higher, 7.4.12 or higher, or 8.0.12 or higher to apply the patch that rejects addresses containing line breaks (see resolution details in the overview).
*   Deploy the Sigma rules provided to detect attempts to exploit this vulnerability by identifying email addresses containing CRLF characters in application logs.
*   Review and audit any code that processes or handles email addresses to ensure proper input validation and sanitization techniques are employed, as an additional layer of defense.
