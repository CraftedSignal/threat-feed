---
title: CVE-2025-14575 Qt Network OpenSSL TLS Backend Uncontrolled Search Path Vulnerability
slug: 2026-05-qt-openssl-path-vuln
description: CVE-2025-14575 describes an uncontrolled search path element vulnerability in the Qt Network OpenSSL TLS backend, allowing for the loading of rogue CA certificates, potentially leading to man-in-the-middle attacks.
date: "2026-05-23T07:18:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openssl
  - tls
  - certificate authority
  - man-in-the-middle
  - path traversal
vendors:
  - Microsoft
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-14575
  - CVE-2025-14575
rules:
  - title: Detect Suspicious CA Certificate Loading via Modified Path
    description: Detects CVE-2025-14575 exploitation — Monitors for process loading CA certificates from unusual or unexpected locations, indicating potential manipulation of the search path.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - windows
  - title: Detect TLS Interception via Modified Certificate Authority
    description: Detects potential TLS interception by monitoring for deviations from known Certificate Authorities.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1588.004
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2025-14575 is an uncontrolled search path element vulnerability residing in the Qt Network component's OpenSSL TLS backend. This flaw allows an attacker to introduce a rogue Certificate Authority (CA) certificate into the system's trust store by manipulating the search path used by Qt to load CA certificates. By exploiting this vulnerability, a malicious actor could potentially intercept and decrypt TLS-protected traffic, conduct man-in-the-middle attacks, and compromise sensitive communications. The vulnerability impacts applications utilizing the vulnerable Qt Network component, particularly those that rely on TLS for secure communication. Defenders should prioritize patching to prevent potential exploitation.

## Attack Chain

1.  Attacker identifies a vulnerable application utilizing the Qt Network component with the flawed OpenSSL TLS backend.
2.  Attacker gains write access to a directory within the application's or system's search path for CA certificates.
3.  Attacker crafts a rogue CA certificate and places it in the attacker-controlled directory within the search path. The rogue certificate is designed to be trusted by the vulnerable application.
4.  The vulnerable application, when initiating a TLS connection, searches for trusted CA certificates using the flawed search path.
5.  The application loads the attacker's rogue CA certificate from the compromised directory.
6.  The application trusts certificates signed by the rogue CA, enabling the attacker to intercept TLS traffic.
7.  Attacker initiates a man-in-the-middle attack by presenting a certificate signed by the rogue CA to the victim application.
8.  The victim application, trusting the rogue CA, accepts the attacker's certificate, allowing the attacker to decrypt and potentially modify the TLS-protected communication.

## Impact

Successful exploitation of CVE-2025-14575 can lead to significant security breaches, including the interception of sensitive data transmitted over TLS. This can impact a wide range of applications, including web browsers, email clients, and other network-aware software. The consequences include data theft, credential compromise, and potential reputational damage for affected organizations. The number of potential victims is directly related to the number of applications utilizing the vulnerable Qt Network component.

## Recommendation

*   Apply the security update provided by Microsoft to address CVE-2025-14575 on systems using the vulnerable Qt Network OpenSSL TLS backend, as referenced in the advisory URL.
*   Deploy the Sigma rule "Detect Suspicious CA Certificate Loading via Modified Path" to identify potential exploitation attempts targeting this vulnerability.
*   Monitor process creation events for applications loading CA certificates from unusual or unexpected locations in the filesystem, as this could indicate an attempt to exploit CVE-2025-14575.
