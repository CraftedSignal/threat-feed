---
title: GNUTLS RSA-PSK Authentication Bypass Vulnerability (CVE-2026-42010)
slug: 2024-01-gnutls-rsa-psk-bypass
description: A vulnerability in GNUTLS (CVE-2026-42010) allows a remote attacker to bypass authentication on servers configured with RSA-PSK by sending a specially crafted username containing a NUL character, leading to unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authentication-bypass
  - vulnerability
  - gnutls
vendors:
  - gnu
products:
  - gnutls
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
cves:
  - id: CVE-2026-42010
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42010
rules:
  - title: Detect GNUTLS RSA-PSK Authentication Bypass Attempt
    description: Detects attempts to exploit CVE-2026-42010 by identifying usernames containing NULL characters during authentication.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - network_connection
      - linux
  - title: Detect GNUTLS Authentication with Suspicious Username Length
    description: Detects potentially malicious authentication attempts where the username length deviates significantly from the norm, possibly indicating a truncated username due to the NULL character vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

CVE-2026-42010 describes an authentication bypass vulnerability affecting GNUTLS, a widely used TLS library. The flaw resides in the handling of RSA-PSK (Rivest–Shamir–Adleman – Pre-Shared Key) configurations. Specifically, servers configured with RSA-PSK incorrectly match usernames containing a NUL character with truncated usernames. This can be exploited remotely by an attacker who sends a specially crafted username that includes a NUL character. The vulnerability was published on 2026-05-07, and exploitation can lead to unauthorized access to affected systems. Defenders should prioritize patching vulnerable GNUTLS installations to prevent potential authentication bypass attacks.

## Attack Chain

1.  Attacker identifies a server utilizing GNUTLS configured with RSA-PSK authentication.
2.  Attacker crafts a malicious username containing a NUL character (e.g., "user\x00name").
3.  Attacker initiates a TLS handshake with the vulnerable server, presenting the crafted username during the RSA-PSK authentication exchange.
4.  The vulnerable GNUTLS server truncates the username at the NUL character ("user") due to the flaw.
5.  The server compares the truncated username with the expected username, potentially leading to a successful match if a user with the prefix exists.
6.  The attacker successfully authenticates to the server without providing the correct credentials.
7.  Attacker gains unauthorized access to resources and services protected by the vulnerable server.

## Impact

Successful exploitation of CVE-2026-42010 allows an attacker to bypass authentication mechanisms, gaining unauthorized access to sensitive resources. The impact includes potential data breaches, service disruption, and privilege escalation within the affected systems. This vulnerability poses a significant risk to organizations relying on GNUTLS for secure communication, especially in environments where RSA-PSK is utilized. The CVSS v3.1 base score of 7.1 indicates a high level of severity, highlighting the urgency for remediation.

## Recommendation

*   Upgrade GNUTLS to a patched version that addresses CVE-2026-42010.
*   Implement the Sigma rule "Detect GNUTLS RSA-PSK Authentication Bypass Attempt" to identify potential exploitation attempts.
*   Review server configurations to minimize the use of RSA-PSK where possible, favoring stronger authentication mechanisms.
*   Monitor authentication logs for suspicious usernames containing NUL characters to detect potential exploitation attempts.
*   Enable verbose logging on GNUTLS servers to capture detailed authentication events for forensic analysis.
