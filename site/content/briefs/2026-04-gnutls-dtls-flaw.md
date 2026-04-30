---
title: GnuTLS DTLS Handshake Parsing Flaw (CVE-2026-33845)
slug: 2026-04-gnutls-dtls-flaw
description: A flaw in GnuTLS DTLS handshake parsing allows malformed fragments with zero length and non-zero offset, leading to an integer underflow during reassembly and resulting in an out-of-bounds read, potentially causing information disclosure or denial of service.
date: "2026-04-30T18:16:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - denial-of-service
  - information-disclosure
  - gnutls
vendors:
  - Red Hat
  - GnuTLS
products:
  - GnuTLS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1068
    technique_name: Proxying
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-33845
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33845
  - https://access.redhat.com/security/cve/CVE-2026-33845
  - https://bugzilla.redhat.com/show_bug.cgi?id=2450624
rules:
  - title: Detect GnuTLS DTLS Malformed Fragment
    description: Detects network connections with malformed DTLS handshake fragments, potentially indicating CVE-2026-33845 exploitation.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
      - information_gathering
    techniques:
      - T1068
      - T1595.002
    data_sources:
      - network_connection
      - zeek
  - title: Detect GnuTLS Integer Underflow via Process Crash
    description: Detects a process crash potentially caused by the integer underflow vulnerability in GnuTLS.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-33845 describes a vulnerability in the GnuTLS library related to the parsing of DTLS handshake fragments. The vulnerability stems from improper handling of malformed fragments that have a zero length but a non-zero offset. This leads to an integer underflow during the reassembly process, which then triggers an out-of-bounds read. The vulnerability is remotely exploitable, meaning an attacker could potentially trigger it without needing local access. Successful exploitation can lead to information disclosure or a denial-of-service condition. The affected component is the GnuTLS library, which is used by various applications for secure communication.

## Attack Chain

1. An attacker crafts a malicious DTLS handshake fragment with a zero length and non-zero offset.
2. The attacker sends the malformed DTLS handshake fragment to a vulnerable GnuTLS server.
3. The GnuTLS library receives the fragment and begins the reassembly process.
4. The integer underflow occurs when calculating the correct offset for the fragment reassembly.
5. The integer underflow leads to an out-of-bounds memory read operation.
6. The out-of-bounds read allows the attacker to potentially read sensitive information from the server's memory.
7. Alternatively, the out-of-bounds read may cause the server to crash, resulting in a denial-of-service.
8. The attacker achieves either information disclosure or denial-of-service based on the server's response to the out-of-bounds read.

## Impact

Successful exploitation of CVE-2026-33845 can lead to a denial-of-service condition, impacting the availability of services relying on the vulnerable GnuTLS library. The out-of-bounds read can also potentially expose sensitive information from the server's memory, leading to data breaches. Given the widespread use of GnuTLS in various applications, a successful widespread attack could affect numerous organizations and users.

## Recommendation

*   Apply available patches for GnuTLS provided by Red Hat or other vendors to address CVE-2026-33845.
*   Monitor network traffic for malformed DTLS handshake fragments with zero length and non-zero offset that may indicate exploitation attempts targeting CVE-2026-33845.
*   Deploy the Sigma rule `DetectGnuTLSDTLSMalformedFragment` to identify suspicious network connections associated with the vulnerability.
