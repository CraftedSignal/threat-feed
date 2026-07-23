---
title: Auth.js Email Normalizer Vulnerability Allows Homoglyph Bypass Leading to Account Takeover
slug: 2026-07-authjs-homoglyph-bypass
description: A critical vulnerability in Auth.js libraries (next-auth and @auth/core) affects the email/magic-link sign-in flow, allowing an attacker to craft an email address with a homoglyph character that bypasses validation before Unicode normalization, leading to magic links being misrouted to attacker-controlled mailboxes and enabling account takeover without victim interaction.
date: "2026-07-23T14:42:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - account-takeover
  - authentication-bypass
  - web-vulnerability
  - magic-link
  - unicode-normalization
vendors:
  - Auth.js
products:
  - next-auth (>= 4.0.0, < 4.24.14)
  - next-auth (>= 4.10.3, < 4.24.15)
  - next-auth (>= 5.0.0-beta.1, <= 5.0.0-beta.31)
  - '@auth/core (>= 0.1.0, < 0.41.3)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The default email-address normalizer used by the email/magic-link sign-in flow validates the address before applying Unicode normalization, allowing a homoglyph @ bypass.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: 'Account takeover: an attacker who knows a victim''s email address can request a magic link that is delivered to an attacker-controlled mailbox, then use it to sign in as the victim.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7rqj-j65f-68wh
---

A critical vulnerability exists in Auth.js, specifically affecting `next-auth` versions `>= 4.0.0, < 4.24.14`, `>= 4.10.3, < 4.24.15`, `>= 5.0.0-beta.1, <= 5.0.0-beta.31` and `@auth/core` versions `>= 0.1.0, < 0.41.3`, when using the default email/magic-link sign-in provider. The flaw stems from the email normalizer validating an address *before* applying Unicode normalization (NFKC/NFKD). This allows an attacker to craft an email address containing a Unicode character that is not an ASCII `@` (U+0040) but canonicalizes to one after normalization. This bypasses the normalizer's single-`@` check, causing a downstream mail library that performs Unicode normalization to interpret the address with two `@` separators. Consequently, the passwordless sign-in link is misrouted to an attacker-controlled mailbox, enabling account takeover without requiring any victim interaction.

## Attack Chain

1. An attacker identifies a target's email address and crafts a malicious version by inserting a Unicode homoglyph character that resembles '@' (e.g., `victim_email[U+XXXX]attacker.com`).
2. The attacker submits this crafted email address to the vulnerable Auth.js application's magic-link sign-in flow.
3. The application's default `normalizeIdentifier` function validates the address, incorrectly perceiving only one '@' symbol because validation occurs prior to Unicode normalization.
4. The application proceeds to send the magic-link email, with the crafted address passed to a downstream mail library or service.
5. The mail library or service, which performs Unicode normalization (e.g., NFKC) for internationalized email, processes the recipient address.
6. During normalization, the homoglyph character in the crafted email canonicalizes to a second '@' symbol (e.g., `victim_email@attacker.com`), causing the mail service to misroute the magic link.
7. The magic link is delivered to the attacker-controlled mailbox, enabling the attacker to authenticate and gain unauthorized access to the victim's account.

## Impact

The primary impact of this vulnerability is account takeover. An attacker who knows a victim's email address can exploit this flaw to request a magic link that is subsequently delivered to an attacker-controlled mailbox. The attacker can then use this link to sign in as the victim, gaining full access to their account. No victim interaction is required for the link to be misrouted, as the attacker initiates and directly receives the authentication link. This can lead to unauthorized access to personal data, financial information, or sensitive corporate resources, depending on the scope and permissions of the compromised account.

## Recommendation

* Upgrade `next-auth` to a patched version (currently pending, refer to GHSA-7rqj-j65f-68wh for updates) immediately.
* Upgrade `@auth/core` to a patched version (currently pending, refer to GHSA-7rqj-j65f-68wh for updates) immediately.
* If immediate upgrade is not possible, implement a custom `normalizeIdentifier` on the email provider that calls `identifier.normalize("NFKC")` *before* any validation, and ensures only one '@' remains after normalization, as detailed in the GHSA advisory.
* Alternatively, as a workaround, reject any email addresses containing non-ASCII characters if your user base does not require internationalized email addresses.
