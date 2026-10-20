---
title: IMAP Command Injection in Roundcube Webmail
slug: 2026-10-roundcube-imap-injection
description: Roundcube Webmail versions prior to 1.6.20 and 1.7.5 are vulnerable to IMAP command injection via CRLF sequences in the _uid parameter, allowing authenticated remote attackers to execute arbitrary IMAP commands.
date: "2026-10-20T06:34:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - imap
  - injection
vendors:
  - Roundcube
products:
  - Webmail (< 1.6.20, 1.7.x < 1.7.5)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A remote authenticated attacker can exploit this via CRLF sequences... to execute arbitrary IMAP commands.
    confidence_band: high
cves:
  - id: CVE-2026-113386
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113386
rules:
  - title: Detect CVE-2026-113386 Exploitation - IMAP Injection via Roundcube
    description: Detects exploitation of CVE-2026-113386 by identifying CRLF injection patterns within the _uid parameter in Roundcube Webmail requests.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Roundcube Webmail to 1.6.20 or 1.7.5
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-113386 advisory
  hunt_leads:
    - lead: Inspect web logs for _uid parameter containing CRLF characters
      technique_id: T1059
      data_needed:
        - web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary IMAP command execution
  mitigation_plan:
    - priority: immediate
      action: Apply security patch to Roundcube instances
      owner: IT Operations
      addresses: CVE-2026-113386
      evidence: NVD report
---

Roundcube Webmail versions before 1.6.20 and 1.7.x before 1.7.5 contain a vulnerability that permits IMAP command injection. This issue occurs due to improper sanitization of user-supplied input within the _uid parameter when processed by the application's mail/headers and mail/viewsource actions. A remote authenticated attacker can leverage this flaw by injecting Carriage Return Line Feed (CRLF) sequences into the targeted parameter. 

Successful exploitation allows the attacker to bypass application logic and send arbitrary commands to the IMAP server associated with the webmail instance. This may lead to unauthorized access to email data, manipulation of mailbox structures, or potential exposure of sensitive information stored on the backend mail server. Security teams should prioritize patching affected instances to the specified secure versions to mitigate this risk.

## Attack Chain

1. The attacker gains authenticated access to a vulnerable Roundcube Webmail instance.
2. The attacker identifies the mail/headers or mail/viewsource actions as endpoints that process the _uid parameter.
3. The attacker crafts an HTTP request targeting one of these actions.
4. The attacker injects malicious CRLF sequences into the _uid parameter string.
5. The application fails to sanitize the input, passing the injected payload to the backend IMAP communication layer.
6. The IMAP server interprets the injected CRLF sequences, executing the attacker-supplied IMAP commands in the context of the user's session.
7. The attacker exfiltrates or manipulates mailbox data through the unauthorized IMAP operations.

## Impact

The vulnerability allows an authenticated attacker to execute arbitrary commands against the backend IMAP server. This can result in unauthorized access to private emails, modification of mailbox contents, and a breach of data confidentiality for users within the organization. While this requires authentication, the impact is severe for multi-user email environments where an attacker might compromise one account to gain unauthorized access to mail data or perform lateral movement within the mail infrastructure.

## Recommendation

* Patch Roundcube Webmail to version 1.6.20 or 1.7.5 or later immediately.
* Monitor web server access logs for anomalous HTTP requests to the mail/headers and mail/viewsource endpoints containing CRLF characters or abnormal IMAP command syntax in the _uid parameter.
* Review web application firewall (WAF) logs for blocked requests attempting to inject line-breaking characters into URL query parameters.
