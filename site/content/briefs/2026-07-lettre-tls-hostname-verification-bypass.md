---
title: Lettré Library TLS Hostname Verification Bypass Vulnerability (CVE-2026-46428)
slug: 2026-07-lettre-tls-hostname-verification-bypass
description: An inverted-boolean bug (CVE-2026-46428) in the `lettre` library's `boring-tls` integration silently disables TLS hostname verification for callers using the default strict configuration, allowing an on-path attacker with any chain-valid certificate to intercept SMTP submission, including credentials and message contents, from affected `lettre` clients.
date: "2026-07-28T14:31:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - tls
  - mitm
  - library-vulnerability
  - rust
  - mail
vendors:
  - lettre
products:
  - lettre (>= 0.10.1, < 0.11.22)
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: An on-path attacker presenting any chain-valid certificate for any domain can intercept SMTP submission, including PLAIN/LOGIN credentials and message contents
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: intercept SMTP submission, including PLAIN/LOGIN credentials
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: intercept SMTP submission, including PLAIN/LOGIN credentials and message contents
    confidence_band: high
cves:
  - id: CVE-2026-46428
    epss: 0.00191
references:
  - https://github.com/advisories/GHSA-4pj9-g833-qx53
---

A critical vulnerability, tracked as CVE-2026-46428, exists in the `lettre` Rust library when compiled with the `boring-tls` feature. This flaw, present in versions 0.10.1 through 0.11.21, stems from an inverted boolean logic error in the `TlsParametersBuilder`'s `accept_invalid_hostnames` flag. Contrary to its intended behavior, the default strict configuration (where `accept_invalid_hostnames` is `false`) causes the underlying `boring` TLS backend to *skip* hostname verification. This creates a severe Man-in-the-Middle (MITM) vulnerability, enabling attackers on the network path to intercept and decrypt SMTP traffic, including authentication credentials and message bodies, by presenting any chain-valid TLS certificate. The bug was introduced in PR #797, commit 985fa7e, and persists across affected versions, bypassing the security expectations of users who believe they have configured strict TLS verification.

## Attack Chain

1. An attacker positions themselves on the network path between a `lettre` client (built with `boring-tls` and using default-strict TLS settings) and its intended SMTP server.
2. The attacker obtains a chain-valid TLS certificate for a domain they control (e.g., via Let's Encrypt for `attacker.example`).
3. The vulnerable `lettre` client initiates an SMTP connection to its target mail exchanger (e.g., `mail.example.com`), configured to use TLS.
4. The attacker's intermediate SMTP server intercepts the connection and presents its certificate (e.g., for `attacker.example`) during the TLS handshake.
5. Due to the inverted boolean logic in `lettre`'s `boring-tls` integration, the `set_verify_hostname(false)` call is made to the `boring` backend, despite the `lettre` client being configured for strict hostname verification (`accept_invalid_hostnames = false`).
6. The `boring` TLS backend, having been instructed to skip hostname verification, successfully completes the TLS handshake with the attacker's certificate, ignoring the mismatch with `mail.example.com`.
7. The `lettre` client proceeds with the SMTP transaction, sending sensitive data such as `MAIL FROM`, `RCPT TO`, message bodies, attachments, headers, and any SMTP AUTH credentials (e.g., PLAIN, LOGIN) to the attacker.
8. The attacker gains full read access to confidential communications and credentials, and can potentially manipulate messages before forwarding or dropping them.

## Impact

This vulnerability severely impacts any `lettre` user deploying applications that utilize the `boring-tls` feature and rely on the default-strict hostname verification settings. Such users are unknowingly susceptible to Man-in-the-Middle attacks, allowing an on-path attacker to intercept all SMTP communications. This includes exposure of sensitive email content, attachments, and crucially, SMTP authentication credentials (PLAIN, LOGIN, CRAM-MD5, etc.). The confidentiality and integrity of email submissions are compromised, leading to potential data breaches, unauthorized access to email accounts, and impersonation. While Cloudflare independently identified and mitigated this downstream, the core vulnerability remains in affected `lettre` versions, requiring an upstream fix to protect all other deployments.

## Recommendation

* Patch CVE-2026-46428 by updating the `lettre` library to version 0.11.22 or newer, which includes the fix.
* If immediate patching is not possible, avoid using the `boring-tls` feature with `lettre` in environments where SMTP traffic is sensitive and subject to MITM risks. Consider switching to `native-tls` or `rustls` backends if feasible, as they are unaffected by this specific bug.
