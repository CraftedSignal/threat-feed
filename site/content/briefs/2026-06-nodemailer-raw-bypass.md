---
title: 'Nodemailer: Message-level raw option bypasses disableFileAccess/disableUrlAccess, enabling arbitrary file read and full-response SSRF'
slug: 2026-06-nodemailer-raw-bypass
description: Nodemailer versions up to 9.0.0 are vulnerable to arbitrary local file read and full-response Server-Side Request Forgery (SSRF) when handling untrusted input for the message-level `raw` option, bypassing intended security flags and allowing sensitive content to be exfiltrated via an attacker-controlled recipient.
date: "2026-06-18T14:54:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - file-read
  - nodemailer
  - nodejs
  - javascript
  - supply-chain
vendors:
  - Nodemailer
products:
  - Nodemailer <= 9.0.0
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-p6gq-j5cr-w38f
iocs:
  - type: url
    value: http://169.254.169.254/
  - type: email
    value: attacker@evil.test
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Nodemailer SSRF Attempts to Internal/Metadata IPs
    description: Detects outbound network connections initiated by Node.js processes targeting common internal IP ranges or cloud metadata service IPs, which could indicate a successful SSRF exploitation of vulnerabilities like GHSA-p6gq-j5cr-w38f in Nodemailer.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - impact
    techniques:
      - T1090.003
      - T1567.002
    data_sources:
      - network_connection
      - linux
  - title: Detect Nodemailer Arbitrary File Read of Sensitive Files
    description: Detects Node.js processes accessing known sensitive files (e.g., /etc/passwd, application .env files, SSH keys) which could indicate successful arbitrary file read exploitation of vulnerabilities like GHSA-p6gq-j5cr-w38f in Nodemailer.
    platform: sigma
    severity: high
    tactics:
      - collection
      - impact
    techniques:
      - T1005
      - T1567.002
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A critical vulnerability exists in Nodemailer versions up to 9.0.0, where the message-level `raw` option can bypass the `disableFileAccess` and `disableUrlAccess` sandboxing flags. This flaw allows an attacker to achieve arbitrary local file disclosure and full-response Server-Side Request Forgery (SSRF). When an application, designed to sandbox untrusted input, calls `transporter.sendMail()` with the `raw` option influenced by an attacker, the `MailComposer.compile()` function fails to propagate these flags to the root MIME node. Consequently, the Nodemailer process will read local files (e.g., `/etc/passwd`) or fetch internal/external URLs (e.g., `http://169.254.169.254/`) and send their contents directly as the email message. This results in the exfiltration of sensitive server-side data to an attacker-specified email address, presenting a high risk to data confidentiality.

## Attack Chain

1.  An application configured to use Nodemailer with `disableFileAccess` and/or `disableUrlAccess` for sandboxing processes untrusted user input.
2.  An attacker crafts malicious input for the `transporter.sendMail()` call, specifically targeting the `raw` message option.
3.  The attacker's input includes a malicious path (e.g., `raw: { path: '/etc/passwd' }`) or a malicious URL (e.g., `raw: { href: 'http://169.254.169.254/latest/meta-data/' }`).
4.  Nodemailer's `MailComposer.compile()` function creates the root MIME node for the `raw` message without correctly applying the `disableFileAccess`/`disableUrlAccess` flags.
5.  The `MimeNode` constructor initializes these flags to `false` by default, effectively ignoring the application's intended sandboxing.
6.  During message compilation, `setRaw()` calls `_getStream()`, which proceeds to read the specified local file or fetch the specified URL, as the security flags are inactive.
7.  The entire content of the read file or the fetched HTTP response body becomes the actual message content of the email.
8.  Nodemailer's transport mechanisms deliver this crafted email, containing sensitive server data, to an email address specified by the attacker (e.g., `attacker@evil.test`).

## Impact

The primary impact of this vulnerability is a high compromise of data confidentiality. Attackers can exfiltrate arbitrary local files from the server, such as `/etc/passwd`, `/proc/self/environ`, application `.env` files, or key material. Additionally, the full-response SSRF capability allows attackers to query internal network services or cloud metadata endpoints (e.g., `169.254.169.254`) and retrieve their full responses. This sensitive information is then delivered directly to an attacker-controlled mailbox, making internal data accessible to external adversaries. The vulnerability directly subverts security controls put in place by the application, rendering them ineffective for the `raw` message type.

## Recommendation

*   **Patch:** Immediately update Nodemailer to a patched version once available. Monitor the official Nodemailer repository and npm for security releases addressing GHSA-p6gq-j5cr-w38f.
*   **Application-level mitigation:** Review all code paths that use `transporter.sendMail()` with the `raw` option. Ensure that untrusted user input cannot directly influence the `path` or `href` properties within the `raw` object. Implement strict input validation and sanitization.
*   **Deployment:** Deploy the provided Sigma rules to your SIEM/EDR to detect attempts at SSRF and suspicious file access by Node.js processes on Linux hosts.
*   **Logging:** Ensure comprehensive logging for process activity, file access, and network connections on servers hosting Node.js applications, particularly on Linux systems, to facilitate detection and investigation.
