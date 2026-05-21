---
title: Hitachi Energy GMS600 Vulnerable to Bleichenbacher Attack via CVE-2022-4304
slug: 2026-05-hitachi-gms600-bleichenbacher
description: Hitachi Energy GMS600 versions 1.3.0 and 1.3.1 are affected by CVE-2022-4304, a vulnerability in the OpenSSL RSA Decryption implementation; an attacker could exploit this timing-based side channel to recover plaintext across a network in a Bleichenbacher-style attack by sending trial messages to the server and recording processing times, eventually decrypting application data.
date: "2026-05-21T16:12:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*
  - cpe:2.3:a:stormshield:endpoint_security:*:*:*:*:*:*:*:*
  - cpe:2.3:a:stormshield:sslvpn:*:*:*:*:*:*:*:*
  - cpe:2.3:a:stormshield:stormshield_network_security:*:*:*:*:*:*:*:*
tags:
  - bleichenbacher
  - timing attack
  - openssl
  - critical infrastructure
vendors:
  - Hitachi Energy
  - OpenSSL
products:
  - GMS600 versions 1.3.0 and 1.3.1
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2022-4304
    cvss: 5.9
    epss: 0.00218
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-01
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-141-01.json
  - https://www.cve.org/CVERecord?id=CVE-2022-4304
rules:
  - title: Detect CVE-2022-4304 Exploitation Attempts — Excessive Connections to GMS600
    description: Detects CVE-2022-4304 exploitation attempts by monitoring for an excessive number of connections to a GMS600 server from a single source IP address, indicative of a Bleichenbacher-style attack
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - firewall
  - title: Detect CVE-2022-4304 Exploitation Attempts — Suspicious TLS Handshake Pattern
    description: Detects CVE-2022-4304 exploitation attempts by monitoring for a suspicious pattern of TLS handshake failures followed by new connection attempts, indicative of an attacker probing for timing differences
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - network_connection
rules_count: 2
---

Hitachi Energy GMS600 versions 1.3.0 and 1.3.1 are vulnerable to a timing-based side-channel attack (CVE-2022-4304) in the OpenSSL RSA decryption implementation. This vulnerability allows a remote attacker to recover plaintext data by exploiting observable discrepancies in processing times. The attack involves sending a large number of trial messages to the server and recording the time taken to process each one. Successful exploitation could allow an attacker to decrypt sensitive application data transmitted over the network. This vulnerability affects all RSA padding modes, including PKCS#1 v1.5, RSA-OEAP, and RSASVE. Hitachi Energy recommends upgrading to version 1.3.2 to mitigate this vulnerability, which was initially disclosed in June 2023 and updated in April 2026.

## Attack Chain

1.  Attacker observes a genuine TLS connection between a client and a server using RSA for key exchange.
2.  Attacker crafts a series of trial messages specifically designed to exploit the timing vulnerability in OpenSSL's RSA decryption implementation.
3.  Attacker sends these trial messages to the GMS600 server.
4.  The GMS600 server processes each trial message, and the attacker records the time taken for each processing attempt.
5.  Attacker analyzes the timing data to identify subtle variations in processing times related to the structure of the encrypted pre-master secret.
6.  After a sufficiently large number of messages, the attacker recovers the pre-master secret used for the original connection.
7.  Attacker decrypts the application data sent over that connection using the recovered pre-master secret.
8.  Attacker gains unauthorized access to sensitive information transmitted between the client and server.

## Impact

Successful exploitation of CVE-2022-4304 allows an attacker to decrypt sensitive data transmitted over the network, potentially compromising critical manufacturing processes controlled by the GMS600. Given the wide deployment of GMS600 in critical infrastructure sectors worldwide, this vulnerability poses a significant risk to operational technology environments. Impact could range from loss of confidentiality to unauthorized control of industrial processes.

## Recommendation

*   Immediately upgrade Hitachi Energy GMS600 to version 1.3.2 to address the vulnerability (CVE-2022-4304).
*   Implement network segmentation and firewall rules to minimize network exposure of control system devices as described in the "General Mitigation Factors" section of the advisory.
*   Enforce ingress IP allowlisting and traffic rate limiting to protect the control network from external attacks.
