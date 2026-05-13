---
title: CVE-2026-0248 Prisma Access Agent Improper Certificate Validation Vulnerability
slug: 2026-05-prisma-access-mitm
description: CVE-2026-0248 is an improper certificate validation vulnerability in Prisma Access Agent for Android and Chrome OS, enabling a man-in-the-middle (MitM) attack to intercept VPN traffic and capture sensitive device information by presenting a certificate issued by a trusted Certificate Authority.
date: "2026-05-13T16:02:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve-2026-0248
  - mitm
  - vpn
  - certificate-validation
vendors:
  - Palo Alto Networks
products:
  - Prisma Access Agent
affected_os:
  - Chrome OS
  - Android
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1557
    technique_name: Man-in-the-Middle
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: Man-in-the-Middle
references:
  - https://security.paloaltonetworks.com/CVE-2026-0248
rules:
  - title: Detect Prisma Access Agent TLS Connection with Untrusted Certificate
    description: Detects a TLS connection from Prisma Access Agent that uses a certificate not issued by a known trusted Certificate Authority; can indicate a MITM attack exploiting CVE-2026-0248.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1557.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Processes Connecting to Port 443 After Prisma Access Connection
    description: Detects processes other than Prisma Access Agent connecting to port 443 after a successful Prisma Access connection, which could indicate a man-in-the-middle attack or traffic redirection.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1557.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-0248 is an improper certificate validation vulnerability affecting Palo Alto Networks Prisma Access Agent versions prior to 26.2.1 on Android and Chrome OS. An attacker can exploit this vulnerability by performing a man-in-the-middle (MitM) attack. By presenting a certificate for any domain issued by a trusted Certificate Authority, the attacker can intercept VPN traffic and capture sensitive device information. This vulnerability does not affect the Prisma Access Agent on macOS, Windows, Linux, or iOS. Palo Alto Networks discovered this issue internally.

## Attack Chain

1.  The attacker positions themselves in a network path between the Android/Chrome OS device and the VPN server.
2.  The user initiates a VPN connection via the Prisma Access Agent.
3.  The attacker intercepts the initial TLS handshake.
4.  The attacker presents a fraudulent certificate for a domain issued by a trusted Certificate Authority.
5.  Due to the improper certificate validation, the Prisma Access Agent on the Android/Chrome OS device accepts the fraudulent certificate.
6.  A secure channel is established between the device and the attacker, appearing as a legitimate VPN connection.
7.  All VPN traffic is now routed through the attacker's machine, allowing the attacker to inspect and modify data in transit.
8.  The attacker captures sensitive device information transmitted through the VPN connection.

## Impact

Successful exploitation of CVE-2026-0248 allows an attacker to perform a man-in-the-middle attack on VPN connections established by the Prisma Access Agent on affected Android and Chrome OS devices. This can lead to the disclosure of sensitive information, such as credentials, personal data, or proprietary business data, transmitted through the VPN. The severity is rated as medium due to the adjacent attack vector.

## Recommendation

*   Upgrade Prisma Access Agent on Android and Chrome OS devices to version 26.2.1 or later to remediate CVE-2026-0248.
*   Deploy the Sigma rules below to detect potential man-in-the-middle attacks targeting Prisma Access Agent connections.
