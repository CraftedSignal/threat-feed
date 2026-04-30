---
title: FreeScout CSS Injection Vulnerability in Mailbox Signature Leads to Privilege Escalation (CVE-2026-40497)
slug: 2026-04-freescout-css-injection
description: FreeScout versions prior to 1.8.213 are vulnerable to CSS injection via the mailbox signature, allowing an attacker with mailbox settings access to exfiltrate CSRF tokens and escalate privileges.
date: "2026-04-21T03:16:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - freescout
  - css-injection
  - privilege-escalation
  - cve-2026-40497
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40497
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40497
rules:
  - title: FreeScout Suspicious Mailbox Signature Update
    description: Detects suspicious updates to the FreeScout mailbox signature field potentially containing CSS injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: FreeScout Mailbox Settings Access
    description: Detects access to the mailbox settings page, which could be a precursor to exploiting CVE-2026-40497.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout, a self-hosted help desk and shared mailbox platform, is susceptible to a CSS injection vulnerability (CVE-2026-40497) in versions prior to 1.8.213. The vulnerability resides within the `Helper::stripDangerousTags()` function, which inadequately sanitizes the mailbox signature field. While the function removes `<script>`, `<form>`, `<iframe>`, and `<object>` tags, it fails to strip `<style>` tags. An attacker with access to mailbox settings, either an administrator or an agent with sufficient permissions, can inject malicious CSS code into the signature field via POST requests to `/mailbox/settings/{id}`. This injected CSS is then rendered unescaped in conversation views using `{!! $conversation->getSignatureProcessed([], true) !!}`. The application's CSP, which allows `style-src * 'self' 'unsafe-inline'`, enables the execution of injected inline styles. This vulnerability allows attackers to exfiltrate CSRF tokens and ultimately escalate privileges.

## Attack Chain

1. Attacker gains access to FreeScout with agent or admin privileges and permission to modify mailbox settings.
2. Attacker navigates to the mailbox settings page.
3. Attacker injects malicious CSS code, including CSS attribute selectors designed to exfiltrate CSRF tokens, into the mailbox signature field via a POST request to `/mailbox/settings/{id}`.  The injected CSS leverages `style-src * 'self' 'unsafe-inline'` in the Content Security Policy.
4. The FreeScout server saves the malicious signature to the database.
5. A victim (another agent or admin) views a conversation within the affected mailbox, causing the malicious signature to be rendered via `{!! $conversation->getSignatureProcessed([], true) !!}`.
6. The injected CSS executes in the victim's browser and exfiltrates the CSRF token, potentially via a DNS request or HTTP request to an attacker-controlled server (not detailed in source).
7. The attacker uses the stolen CSRF token to perform unauthorized actions on behalf of the victim.
8. The attacker escalates privileges by creating new admin accounts or modifying existing user credentials.

## Impact

Successful exploitation of this vulnerability allows an attacker to escalate privileges from an agent to an administrator within the FreeScout platform. This could lead to a complete compromise of the help desk system. An attacker could create new administrator accounts, modify existing user credentials, access sensitive customer data, and potentially disrupt the entire help desk operation. While the exact number of potentially affected FreeScout instances is unknown, all installations prior to version 1.8.213 are vulnerable if an attacker gains valid access.

## Recommendation

*   Upgrade FreeScout to version 1.8.213 or later to apply the updated fix for CVE-2026-40497.
*   Implement the Sigma rule "FreeScout Suspicious Mailbox Signature Update" to detect attempts to inject CSS into the mailbox signature field.
*   Monitor web server logs for POST requests to `/mailbox/settings/{id}` and inspect the request body for `<style>` tags or suspicious CSS syntax to potentially detect attempted exploitation (webserver log source).
