---
title: Net::IMAP STARTTLS Stripping Vulnerability
slug: 2026-05-net-imap-starttls-stripping
description: A man-in-the-middle attacker can exploit a vulnerability in Net::IMAP's STARTTLS implementation to bypass TLS encryption, leading to cleartext transmission of sensitive information by injecting a spoofed 'OK' response during the TLS negotiation.
date: "2026-05-05T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - tls-stripping
  - man-in-the-middle
  - net-imap
  - cve-2026-42246
vendors:
  - rubygems
products:
  - net-imap (>= 0.6.0, <= 0.6.3)
  - net-imap (>= 0.5.0, <= 0.5.13)
  - net-imap (>= 0.4.0, <= 0.4.23)
  - net-imap (>= 0, <= 0.3.9)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Credentials
references:
  - https://github.com/advisories/GHSA-vcgp-9326-pqcp
  - https://www.rfc-editor.org/info/rfc8314
  - https://nostarttls.secvuln.info/
rules:
  - title: Detect STARTTLS Command in Network Traffic
    description: Detects the STARTTLS command being sent over a network connection, which is the initial step in exploiting CVE-2026-42246.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1558
      - T1558.003
    data_sources:
      - network_connection
      - zeek
  - title: Detect Cleartext IMAP Login After STARTTLS
    description: Detects an IMAP LOGIN command sent in cleartext after a STARTTLS command was supposedly negotiated, indicating a potential stripping attack.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1558
      - T1558.003
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

A critical vulnerability exists within the Net::IMAP library, affecting versions 0.6.0 through 0.6.3, 0.5.0 through 0.5.13, 0.4.0 through 0.4.23, and 0 through 0.3.9. This flaw allows a man-in-the-middle (MitM) attacker to perform a STARTTLS stripping attack. By injecting a specially crafted, tagged "OK" response with a predictable tag before the client completes sending the STARTTLS command, the client prematurely believes TLS negotiation has succeeded. Consequently, the TLS connection is never established, leaving subsequent communication unencrypted. This vulnerability, identified as CVE-2026-42246, enables attackers to intercept and potentially steal sensitive data transmitted in cleartext. Defenders should prioritize patching or implementing mitigations to prevent exploitation.

## Attack Chain

1.  The client initiates a plaintext IMAP connection to the server.
2.  The client issues a `STARTTLS` command to initiate TLS negotiation.
3.  The MitM attacker intercepts the `STARTTLS` command.
4.  The attacker injects a spoofed `OK` response with a predictable tag before the IMAP server responds.
5.  The `Net::IMAP#starttls` method returns "successfully" due to the premature `OK` response.
6.  The TLS connection is never established, and the socket remains unencrypted.
7.  The client continues communication, sending sensitive data (usernames, passwords, emails) in cleartext.
8.  The attacker intercepts the cleartext data, compromising the client's account and potentially gaining access to sensitive information.

## Impact

Successful exploitation of this vulnerability results in a complete bypass of TLS encryption for IMAP communication. This allows a man-in-the-middle attacker to eavesdrop on sensitive information transmitted between the client and the server, including usernames, passwords, email content, and other confidential data. The vulnerability poses a significant risk to any application using the affected versions of the `net-imap` gem, potentially impacting a large number of users and organizations.

## Recommendation

*   Upgrade to a patched version of the `net-imap` gem that raises an exception when `#starttls` fails to establish TLS, as described in the advisory.
*   If upgrading is not immediately feasible, explicitly verify `Net::IMAP#tls_verified?` returns `true` after calling `#starttls` before transmitting any sensitive data.
*   Consider using implicit TLS connections (connecting directly to a TLS port) instead of relying on `STARTTLS`, following the recommendations in RFC 8314.
