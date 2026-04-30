---
title: FreeScout Mass Assignment Vulnerability (CVE-2026-40569)
slug: 2026-04-freescout-mass-assignment
description: FreeScout versions prior to 1.8.213 contain a mass assignment vulnerability allowing authenticated admins to modify sensitive mailbox settings by injecting parameters into connection settings requests, leading to email exfiltration and account compromise.
date: "2026-04-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - freescout
  - mass-assignment
  - vulnerability
  - email-exfiltration
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40569
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40569
rules:
  - title: Detect FreeScout Mailbox Settings Modification via POST Request
    description: Detects POST requests to the mailbox settings endpoints with suspicious parameters indicating potential mass assignment exploitation.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect FreeScout Auto BCC Setting Change
    description: Detects modifications to the auto_bcc setting, which can indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout, a self-hosted help desk and shared mailbox platform, is vulnerable to a mass assignment flaw (CVE-2026-40569) in versions prior to 1.8.213. The vulnerability resides in the `connectionIncomingSave()` and `connectionOutgoingSave()` methods within `app/Http/Controllers/MailboxesController.php`.  These methods lack proper input validation, allowing an authenticated administrator to overwrite critical mailbox settings by injecting arbitrary parameters into legitimate connection setting update requests. Attackers can modify fields like `auto_bcc`, `out_server`, `out_password`, `signature`, `auto_reply_enabled`, and `auto_reply_message`. This issue allows malicious actors to silently surveil communications, redirect SMTP traffic, inject malicious content, and persistently compromise email accounts. The impact is particularly severe in multi-admin environments or when an admin session is compromised through other means (e.g., XSS). FreeScout version 1.8.213 addresses this vulnerability.

## Attack Chain

1. An attacker gains authenticated access to the FreeScout admin panel, either through legitimate credentials or by exploiting another vulnerability (e.g., XSS).
2. The attacker navigates to the mailbox connection settings page.
3. The attacker crafts a legitimate request to update connection settings, such as IMAP or SMTP server details.
4. The attacker injects malicious parameters into the request, such as `auto_bcc=attacker@evil.com`, which are not directly exposed in the connection settings form.
5. The FreeScout application, due to the mass assignment vulnerability in `connectionIncomingSave()` or `connectionOutgoingSave()`, processes the injected parameters and updates the corresponding mailbox settings in the database.
6.  When `auto_bcc` is set, every outgoing email from the compromised mailbox is silently BCC'd to the attacker-controlled email address via the `SendReplyToCustomer` job.
7. Alternatively, the attacker could modify the `out_server` and `out_password` fields to redirect outgoing SMTP traffic through an attacker-controlled server.
8. The attacker gains persistent access to all outgoing email from the affected mailbox, enabling data exfiltration or further malicious activities like phishing.

## Impact

Successful exploitation of this vulnerability can lead to complete compromise of FreeScout mailboxes. An attacker could silently exfiltrate sensitive email communications, potentially impacting hundreds or thousands of users depending on the size of the organization. The injected parameters persist even after the initial attack, providing long-term access. This is especially dangerous in organizations that handle sensitive customer data or financial information. The ability to redirect SMTP traffic and inject malicious content further amplifies the risk, potentially leading to widespread phishing campaigns and reputational damage.

## Recommendation

*   Upgrade FreeScout to version 1.8.213 or later to patch CVE-2026-40569 immediately.
*   Implement strict input validation and sanitization for all user-supplied data, particularly in the `connectionIncomingSave()` and `connectionOutgoingSave()` methods, to prevent mass assignment vulnerabilities.
*   Review existing FreeScout installations for any unauthorized modifications to mailbox settings, specifically focusing on `auto_bcc`, `out_server`, `out_password`, `signature`, `auto_reply_enabled`, and `auto_reply_message` fields (requires direct database inspection).
*   Monitor FreeScout webserver logs for POST requests to `/mailboxes/*/connection/incoming-save` and `/mailboxes/*/connection/outgoing-save` endpoints containing unexpected parameters to detect potential exploitation attempts (see example Sigma rule below).
*   Enable webserver logging and ensure that POST request bodies are captured to facilitate investigation and detection.
