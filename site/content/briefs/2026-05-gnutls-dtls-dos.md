---
title: GnuTLS DTLS Packet Reordering Vulnerability (CVE-2026-42009)
slug: 2026-05-gnutls-dtls-dos
description: A remote attacker could exploit a flaw in GnuTLS's DTLS packet reordering logic (CVE-2026-42009) to cause unstable packet ordering or undefined behavior, resulting in a denial of service.
date: "2026-05-18T13:17:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - gnutls
  - dtls
  - dos
  - cve-2026-42009
vendors:
  - GnuTLS
products:
  - GnuTLS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2026-42009
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42009
rules:
  - title: Detect CVE-2026-42009 - DTLS Packet Reordering DoS Attempt
    description: Detects a potential DoS attack via malformed DTLS packets with duplicated sequence numbers targeting CVE-2026-42009.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - zeek
  - title: Detect CVE-2026-42009 - Potential DoS - High CPU Usage by GnuTLS Application
    description: Detects potential denial of service attempts against GnuTLS applications, based on unusually high CPU usage, related to CVE-2026-42009.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A denial-of-service vulnerability, tracked as CVE-2026-42009, exists within the GnuTLS library. The vulnerability stems from improper handling of Datagram Transport Layer Security (DTLS) packets with duplicate sequence numbers. The comparator function, responsible for ordering DTLS packets, does not correctly manage packets with duplicate sequence numbers. A remote attacker could exploit this vulnerability by sending specially crafted DTLS packets, leading to unstable packet ordering or undefined behavior within the GnuTLS library. Successful exploitation could result in a denial-of-service condition, impacting applications and services that rely on GnuTLS for secure communication. This vulnerability affects the GnuTLS library, potentially impacting a wide range of applications.

## Attack Chain

1.  Attacker identifies a service using a vulnerable version of GnuTLS with DTLS enabled.
2.  Attacker establishes a DTLS connection with the target service.
3.  Attacker sends a series of DTLS packets with intentionally duplicated sequence numbers.
4.  The vulnerable GnuTLS library attempts to reorder the packets based on their sequence numbers.
5.  Due to the duplicated sequence numbers, the comparator function fails to correctly order the packets.
6.  The packet reordering logic enters an unstable state or exhibits undefined behavior.
7.  The GnuTLS library consumes excessive resources attempting to process the malformed packet stream.
8.  The service becomes unresponsive, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-42009 results in a denial-of-service condition. This means the targeted service becomes unavailable to legitimate users. The severity of the impact depends on the criticality of the affected service. There is no information about specific victims or sectors targeted available.

## Recommendation

*   Monitor network traffic for DTLS connections and unusual patterns in DTLS packet sequence numbers, using the network connection rule below.
*   Deploy the process creation rule to detect unusual processes initiated during a potential denial of service condition.
*   Upgrade GnuTLS to the latest version to patch CVE-2026-42009.
